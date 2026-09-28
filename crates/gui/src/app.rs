//! The window: navigation, pages and state. All text that comes from
//! scanned files, rules or the service is escaped before display
//! (`safe`); egui draws text as glyphs only, with no markup or links, so a
//! hostile file name can neither run code nor trigger an action.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Instant;

use eframe::egui::{self, Color32, RichText};
use uuid::Uuid;
use warden_core::{Finding, FindingTarget, ObservedPath, ScanReport, ScanStatus, Severity};
use warden_ipc::{JobKind, Op, QuarantineItem, ScheduleInfo, ServiceStatus};

use crate::tasks::{self, CancelHandle, Event, Progress, ScanRequest, UpdateInfo};

/// Longest untrusted text shown in lists (details show everything).
const LIST_TEXT_CHARS: usize = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Page {
    Status,
    Scan,
    Results,
    Update,
    Quarantine,
}

#[derive(Debug)]
enum ServiceState {
    Checking,
    Connected(ServiceStatus),
    Absent(String),
}

#[derive(Debug)]
struct Running {
    started: Instant,
    progress: Progress,
    cancel: CancelHandle,
    job: Option<Uuid>,
}

#[derive(Debug)]
enum Confirm {
    Restore(QuarantineItem),
    Delete(QuarantineItem),
}

pub(crate) struct App {
    tx: Sender<Event>,
    rx: Receiver<Event>,
    ctx: egui::Context,
    logo: Option<egui::TextureHandle>,
    page: Page,
    service: ServiceState,
    use_service: bool,
    // Scan form.
    paths: Vec<PathBuf>,
    new_path: String,
    heuristics: bool,
    archives: bool,
    installed_content: bool,
    running: Option<Running>,
    // Results.
    report: Option<ScanReport>,
    scan_error: Option<String>,
    messages: Vec<String>,
    selected: Option<usize>,
    // Update.
    updating: bool,
    update_result: Option<Result<UpdateInfo, String>>,
    // Service lists.
    quarantine: Option<Result<Vec<QuarantineItem>, String>>,
    schedules: Option<Result<Vec<ScheduleInfo>, String>>,
    action: Option<Result<String, String>>,
    confirm: Option<Confirm>,
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App")
            .field("page", &self.page)
            .finish_non_exhaustive()
    }
}

/// Untrusted text made inert for display.
fn safe(s: &str) -> String {
    warden_core::text::escape_unsafe_chars(s)
}

fn short(s: &str) -> String {
    if s.chars().count() <= LIST_TEXT_CHARS {
        s.to_owned()
    } else {
        let mut t: String = s.chars().take(LIST_TEXT_CHARS).collect();
        t.push('…');
        t
    }
}

fn path_text(p: &ObservedPath) -> String {
    let mut s = safe(&p.text);
    if p.is_lossy() {
        s.push_str("  [name is not valid Unicode]");
    }
    s
}

/// A snake_case enum value as words ("potentially_unwanted" -> "potentially unwanted").
fn label<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.replace('_', " ")))
        .unwrap_or_default()
}

fn severity_color(s: Severity) -> Color32 {
    match s {
        Severity::Critical => Color32::from_rgb(220, 50, 50),
        Severity::High => Color32::from_rgb(230, 120, 40),
        Severity::Medium => Color32::from_rgb(220, 180, 40),
        Severity::Low => Color32::from_rgb(90, 150, 230),
        _ => Color32::GRAY,
    }
}

fn target_text(t: &FindingTarget) -> String {
    match t {
        FindingTarget::File { path, .. } => path_text(path),
        FindingTarget::ArchiveMember {
            archive, member, ..
        } => {
            let mut s = path_text(archive);
            for m in member {
                s.push_str(" > ");
                s.push_str(&path_text(m));
            }
            s
        }
        FindingTarget::Persistence {
            location, entry, ..
        } => match entry {
            Some(e) => format!("{} ({})", path_text(location), safe(e)),
            None => path_text(location),
        },
        FindingTarget::Process { pid, name, .. } => format!("process {pid} ({})", safe(name)),
        FindingTarget::System { component } => safe(component),
        _ => "(unknown target)".to_owned(),
    }
}

fn target_sha256(t: &FindingTarget) -> Option<String> {
    match t {
        FindingTarget::File { sha256, .. } | FindingTarget::ArchiveMember { sha256, .. } => {
            sha256.as_ref().map(ToString::to_string)
        }
        _ => None,
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    #[allow(clippy::cast_precision_loss)]
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// The user's home and Downloads folders, when they exist.
fn common_folders() -> Vec<(&'static str, PathBuf)> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .filter(|p| p.is_dir());
    let mut out = Vec::new();
    if let Some(h) = home {
        let downloads = h.join("Downloads");
        if downloads.is_dir() {
            out.push(("Downloads", downloads));
        }
        out.push(("Home folder", h));
    }
    out
}

impl App {
    pub(crate) fn new(
        cc: &eframe::CreationContext<'_>,
        icon: Option<&eframe::egui::IconData>,
    ) -> Self {
        let app = Self::with_context(cc.egui_ctx.clone(), icon);
        tasks::service_status(app.tx.clone(), app.repaint());
        app
    }

    /// The app without looking for the service (tests start here).
    fn with_context(ctx: egui::Context, icon: Option<&eframe::egui::IconData>) -> Self {
        let (tx, rx) = channel();
        let logo = icon.map(|i| {
            let image = egui::ColorImage::from_rgba_unmultiplied(
                [i.width as usize, i.height as usize],
                &i.rgba,
            );
            ctx.load_texture("logo", image, egui::TextureOptions::LINEAR)
        });
        Self {
            tx,
            rx,
            ctx,
            logo,
            page: Page::Status,
            service: ServiceState::Checking,
            use_service: false,
            paths: Vec::new(),
            new_path: String::new(),
            heuristics: false,
            archives: true,
            installed_content: true,
            running: None,
            report: None,
            scan_error: None,
            messages: Vec::new(),
            selected: None,
            updating: false,
            update_result: None,
            quarantine: None,
            schedules: None,
            action: None,
            confirm: None,
        }
    }

    fn repaint(&self) -> impl Fn() + Send + 'static {
        let ctx = self.ctx.clone();
        move || ctx.request_repaint()
    }

    fn service_connected(&self) -> Option<&ServiceStatus> {
        match &self.service {
            ServiceState::Connected(s) => Some(s),
            _ => None,
        }
    }

    fn via_service(&self) -> bool {
        self.use_service && self.service_connected().is_some()
    }

    fn handle_events(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                Event::Service(Ok(s)) => {
                    self.service = ServiceState::Connected(*s);
                    self.use_service = true;
                }
                Event::Service(Err(e)) => self.service = ServiceState::Absent(e),
                Event::Progress(p) => {
                    if let Some(r) = &mut self.running {
                        r.progress = p;
                    }
                }
                Event::JobStarted(job) => {
                    if let Some(r) = &mut self.running {
                        r.job = Some(job);
                    }
                }
                Event::ScanDone { result, messages } => {
                    self.running = None;
                    self.messages = messages;
                    self.selected = None;
                    match result {
                        Ok(report) => {
                            self.report = Some(*report);
                            self.scan_error = None;
                        }
                        Err(e) => {
                            self.report = None;
                            self.scan_error = Some(e);
                        }
                    }
                    self.page = Page::Results;
                }
                Event::UpdateDone(r) => {
                    self.updating = false;
                    self.update_result = Some(r);
                }
                Event::Quarantine(r) => self.quarantine = Some(r),
                Event::Schedules(r) => self.schedules = Some(r),
                Event::Done(r) => {
                    self.action = Some(r);
                    // Lists may have changed.
                    if self.page == Page::Quarantine {
                        tasks::quarantine_list(self.tx.clone(), self.repaint());
                    }
                }
            }
        }
    }

    fn start_scan(&mut self) {
        let req = ScanRequest {
            paths: self.paths.clone(),
            heuristics: self.heuristics,
            archives: self.archives,
            installed_content: self.installed_content,
        };
        let cancel = CancelHandle::default();
        if self.via_service() {
            tasks::scan_service(req, self.tx.clone(), self.repaint());
        } else {
            tasks::scan_local(req, cancel.clone(), self.tx.clone(), self.repaint());
        }
        self.running = Some(Running {
            started: Instant::now(),
            progress: Progress::default(),
            cancel,
            job: None,
        });
    }

    fn cancel_scan(&self) {
        if let Some(r) = &self.running {
            match r.job {
                Some(job) => tasks::cancel_service_job(job),
                None => r.cancel.cancel_local(),
            }
        }
    }

    // ------------------------------------------------------------------
    // Pages

    fn nav(&mut self, ui: &mut egui::Ui) {
        if let Some(logo) = &self.logo {
            ui.vertical_centered(|ui| {
                ui.add(egui::Image::new(logo).fit_to_exact_size(egui::vec2(96.0, 96.0)));
            });
        }
        ui.vertical_centered(|ui| {
            ui.heading("Abyssal Warden");
            ui.label(RichText::new(format!("version {}", env!("CARGO_PKG_VERSION"))).small());
        });
        ui.separator();
        for (page, name) in [
            (Page::Status, "Status"),
            (Page::Scan, "Scan"),
            (Page::Results, "Results"),
            (Page::Update, "Detection content"),
            (Page::Quarantine, "Quarantine"),
        ] {
            if ui.selectable_label(self.page == page, name).clicked() {
                self.page = page;
                self.on_page_opened();
            }
        }
        ui.separator();
        match &self.service {
            ServiceState::Checking => {
                ui.label("Service: checking…");
            }
            ServiceState::Connected(_) => {
                ui.label(RichText::new("Service: connected").color(Color32::from_rgb(80, 180, 90)));
            }
            ServiceState::Absent(_) => {
                ui.label("Service: not running (standalone)");
            }
        }
    }

    fn on_page_opened(&mut self) {
        match self.page {
            Page::Quarantine if self.service_connected().is_some() => {
                tasks::quarantine_list(self.tx.clone(), self.repaint());
            }
            Page::Update if self.service_connected().is_some() => {
                tasks::schedules(self.tx.clone(), self.repaint());
            }
            _ => {}
        }
    }

    fn status_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Status");
        ui.add_space(8.0);
        match &self.service {
            ServiceState::Checking => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Looking for the background service…");
                });
            }
            ServiceState::Connected(s) => {
                ui.label(format!(
                    "The background service (abyssal-wardend {}) is running. Jobs running: {}, queued: {}, schedules: {}.",
                    safe(&s.server_version),
                    s.jobs_running,
                    s.jobs_queued,
                    s.schedules
                ));
                ui.label(if s.caller_is_admin {
                    "You are an administrator of the service: you can manage quarantine and schedules."
                } else {
                    "You are not an administrator of the service: scans run with your own permissions."
                });
                ui.checkbox(&mut self.use_service, "Run scans through the service");
            }
            ServiceState::Absent(reason) => {
                ui.label("The background service is not running, so the app works standalone: scans run as you, with your permissions, and scheduled scans and quarantine management are not available here.");
                ui.label(RichText::new(safe(reason)).small().weak());
                if ui.button("Check again").clicked() {
                    self.service = ServiceState::Checking;
                    tasks::service_status(self.tx.clone(), self.repaint());
                }
            }
        }
        ui.add_space(16.0);
        ui.heading("What this app can and cannot do");
        ui.label(
            "Abyssal Warden is in early development and must not be relied on to protect a system.",
        );
        for line in [
            "It scans files on request or on a schedule. It has no real-time protection: nothing is checked when files are opened.",
            "It detects files matching its detection content (hashes and YARA rules from open feeds) and, if enabled, suspicious structure (heuristics). Detection rates have not been measured.",
            "System checks run inside the running system. A kernel-level rootkit can hide from them; only an offline scan from trusted media gives a trustworthy answer.",
            "Nothing is quarantined or deleted unless you ask for it.",
        ] {
            ui.label(format!("• {line}"));
        }
    }

    fn scan_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scan");
        ui.add_space(8.0);
        let busy = self.running.is_some();
        ui.add_enabled_ui(!busy, |ui| {
            ui.label("Folders and files to scan:");
            let mut remove = None;
            for (i, p) in self.paths.iter().enumerate() {
                ui.horizontal(|ui| {
                    if ui.small_button("Remove").clicked() {
                        remove = Some(i);
                    }
                    ui.label(safe(&p.to_string_lossy()));
                });
            }
            if let Some(i) = remove {
                self.paths.remove(i);
            }
            if self.paths.is_empty() {
                ui.label(RichText::new("Nothing selected yet.").weak());
            }
            ui.horizontal_wrapped(|ui| {
                for (name, path) in common_folders() {
                    if ui.button(format!("Add {name}")).clicked() && !self.paths.contains(&path) {
                        self.paths.push(path);
                    }
                }
                if ui.button("Choose folder…").clicked()
                    && let Some(dirs) = rfd::FileDialog::new().pick_folders()
                {
                    for d in dirs {
                        if !self.paths.contains(&d) {
                            self.paths.push(d);
                        }
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("Or type a path:");
                let edit = ui.text_edit_singleline(&mut self.new_path);
                let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if (ui.button("Add").clicked() || enter) && !self.new_path.trim().is_empty() {
                    let p = PathBuf::from(self.new_path.trim());
                    if !self.paths.contains(&p) {
                        self.paths.push(p);
                    }
                    self.new_path.clear();
                }
            });
            ui.add_space(8.0);
            ui.checkbox(&mut self.heuristics, "Heuristics: also flag suspicious structure (packed programs, odd scripts). Review-only findings.");
            ui.checkbox(&mut self.archives, "Look inside ZIP archives (JAR, APK, Office documents)");
            if !self.via_service() {
                ui.checkbox(&mut self.installed_content, "Use installed detection content (see Detection content)");
            }
        });
        ui.add_space(12.0);
        if let Some(r) = &self.running {
            let p = r.progress;
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(format!(
                    "Scanning… {} files ({}), {} findings, {} skipped, {} issues, {}s",
                    p.files_scanned,
                    human_bytes(p.bytes_scanned),
                    p.findings,
                    p.entries_skipped,
                    p.issues,
                    r.started.elapsed().as_secs()
                ));
            });
            if r.job.is_some() {
                ui.label(
                    RichText::new("Running in the service; live counts are not available.").weak(),
                );
            }
            if ui.button("Cancel").clicked() {
                self.cancel_scan();
            }
        } else if ui
            .add_enabled(
                !self.paths.is_empty(),
                egui::Button::new(RichText::new("Start scan").strong()),
            )
            .clicked()
        {
            self.start_scan();
        }
    }

    fn results_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Results");
        ui.add_space(8.0);
        if let Some(e) = &self.scan_error {
            ui.label(
                RichText::new(format!("The scan did not finish: {}", safe(e)))
                    .color(Color32::from_rgb(220, 80, 80)),
            );
            if e.contains("no installed content") {
                ui.label("Install detection content on the Detection content page, or untick \"Use installed detection content\".");
            }
        }
        let Some(report) = &self.report else {
            if self.scan_error.is_none() {
                ui.label("No scan yet. Start one on the Scan page.");
            }
            self.messages_section(ui);
            return;
        };
        let s = &report.stats;
        let status = match report.status {
            ScanStatus::Completed => "completed",
            ScanStatus::Cancelled => "cancelled (partial results)",
            ScanStatus::TimeLimitReached => "stopped at the time limit (partial results)",
            _ => "unknown",
        };
        ui.label(format!(
            "Scan {status}: {} files ({}), {} findings, {} skipped, {} issues.",
            s.files_scanned,
            human_bytes(s.bytes_scanned),
            report.findings.len(),
            s.entries_skipped,
            s.issues
        ));
        if report.detectors.is_empty() {
            ui.label(RichText::new("No detection content was used: files were only hashed, not checked for threats.").color(Color32::from_rgb(230, 120, 40)));
        }
        for w in &report.warnings {
            ui.label(RichText::new(format!("Warning: {}", safe(w))).weak());
        }
        ui.add_space(8.0);
        if report.findings.is_empty() {
            ui.label("Nothing was found.");
        }
        // Most severe first; the report order breaks ties.
        let mut order: Vec<usize> = (0..report.findings.len()).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(report.findings[i].severity));
        let mut clicked = None;
        egui::ScrollArea::vertical()
            .max_height(ui.available_height() * 0.45)
            .id_salt("findings")
            .show(ui, |ui| {
                egui::Grid::new("findings-grid")
                    .striped(true)
                    .num_columns(3)
                    .show(ui, |ui| {
                        for &i in &order {
                            let f = &report.findings[i];
                            ui.label(
                                RichText::new(label(&f.severity).to_uppercase())
                                    .color(severity_color(f.severity))
                                    .strong(),
                            );
                            if ui
                                .selectable_label(self.selected == Some(i), short(&safe(&f.name)))
                                .clicked()
                            {
                                clicked = Some(i);
                            }
                            ui.label(short(&target_text(&f.target)));
                            ui.end_row();
                        }
                    });
            });
        if clicked.is_some() {
            self.selected = clicked;
        }
        if let Some(f) = self.selected.and_then(|i| report.findings.get(i)) {
            ui.separator();
            egui::ScrollArea::vertical()
                .id_salt("details")
                .show(ui, |ui| details(ui, f));
        }
        self.messages_section(ui);
    }

    fn messages_section(&self, ui: &mut egui::Ui) {
        if !self.messages.is_empty() {
            egui::CollapsingHeader::new(format!("Scanner messages ({})", self.messages.len()))
                .show(ui, |ui| {
                    for m in &self.messages {
                        ui.label(RichText::new(m).monospace().small());
                    }
                });
        }
    }

    fn update_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Detection content");
        ui.add_space(8.0);
        ui.label("Detection content (malware hashes and YARA rules) is downloaded from the project's signed update channel. Every file is checked against the project's keys before it is used; nothing is installed if any check fails.");
        ui.add_space(8.0);
        ui.label("For your account:");
        if self.updating {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Checking for updates…");
            });
        } else if ui.button("Check for updates now").clicked() {
            self.updating = true;
            self.update_result = None;
            tasks::update_local(self.tx.clone(), self.repaint());
        }
        match &self.update_result {
            Some(Ok(u)) => {
                ui.label(format!(
                    "{} \"{}\", sequence {}. Update channel valid until {}.",
                    if u.changed {
                        "Installed"
                    } else {
                        "Up to date:"
                    },
                    u.bundle,
                    u.sequence,
                    u.expires
                ));
            }
            Some(Err(e)) => {
                ui.label(
                    RichText::new(format!("Update failed: {}", safe(e)))
                        .color(Color32::from_rgb(220, 80, 80)),
                );
                if e.contains("not found") {
                    ui.label("The update channel may not have published any content yet.");
                }
            }
            None => {}
        }
        if self.service_connected().is_some() {
            ui.add_space(12.0);
            ui.label("The service keeps its own content up to date with update schedules:");
            match &self.schedules {
                None => {
                    ui.spinner();
                }
                Some(Err(e)) => {
                    ui.label(safe(e));
                }
                Some(Ok(list)) => {
                    let updates: Vec<&ScheduleInfo> =
                        list.iter().filter(|s| s.kind == JobKind::Update).collect();
                    if updates.is_empty() {
                        ui.label(
                            RichText::new(
                                "No update schedule is configured (see docs/user/updates.md).",
                            )
                            .weak(),
                        );
                    }
                    let mut run = None;
                    for s in updates {
                        ui.horizontal(|ui| {
                            ui.label(format!("{}: every {} hours", safe(&s.name), s.every_hours));
                            if ui.button("Run now").clicked() {
                                run = Some(s.name.clone());
                            }
                        });
                    }
                    if let Some(name) = run {
                        tasks::service_action(
                            Op::RunSchedule { name },
                            self.tx.clone(),
                            self.repaint(),
                        );
                    }
                }
            }
            self.action_line(ui);
        }
    }

    fn action_line(&self, ui: &mut egui::Ui) {
        match &self.action {
            Some(Ok(m)) => {
                ui.label(RichText::new(m).color(Color32::from_rgb(80, 180, 90)));
            }
            Some(Err(e)) => {
                ui.label(RichText::new(safe(e)).color(Color32::from_rgb(220, 80, 80)));
            }
            None => {}
        }
    }

    fn quarantine_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Quarantine");
        ui.add_space(8.0);
        if self.service_connected().is_none() {
            ui.label("Quarantine management in the app goes through the background service, which is not running. Use the command line instead: abyssal-warden quarantine list.");
            return;
        }
        if ui.button("Refresh").clicked() {
            tasks::quarantine_list(self.tx.clone(), self.repaint());
        }
        self.action_line(ui);
        match &self.quarantine {
            None => {
                ui.spinner();
            }
            Some(Err(e)) => {
                ui.label(safe(e));
            }
            Some(Ok(items)) if items.is_empty() => {
                ui.label("Nothing is quarantined.");
            }
            Some(Ok(items)) => {
                let mut confirm = None;
                egui::ScrollArea::vertical().show(ui, |ui| {
                    egui::Grid::new("quarantine-grid")
                        .striped(true)
                        .num_columns(4)
                        .show(ui, |ui| {
                            for item in items {
                                ui.label(short(&safe(&item.original_path)));
                                ui.label(short(&safe(&item.reason)));
                                ui.label(item.created_at.date().to_string());
                                ui.horizontal(|ui| {
                                    if ui.button("Restore…").clicked() {
                                        confirm = Some(Confirm::Restore(item.clone()));
                                    }
                                    if ui.button("Delete…").clicked() {
                                        confirm = Some(Confirm::Delete(item.clone()));
                                    }
                                });
                                ui.end_row();
                            }
                        });
                });
                if confirm.is_some() {
                    self.confirm = confirm;
                }
            }
        }
    }

    fn confirm_window(&mut self, ctx: &egui::Context) {
        let Some(c) = &self.confirm else { return };
        let (title, text, item) = match c {
            Confirm::Restore(i) => (
                "Restore file?",
                "The file goes back to its original location and is allow-listed, so later scans no longer report it. Only do this if you are sure it is safe.",
                i,
            ),
            Confirm::Delete(i) => (
                "Delete file permanently?",
                "The quarantined copy is deleted. This cannot be undone.",
                i,
            ),
        };
        let mut decision = None;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.label(safe(&item.original_path));
                ui.label(
                    RichText::new(format!("SHA-256 {}", safe(&item.sha256)))
                        .monospace()
                        .small(),
                );
                ui.label(text);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        decision = Some(false);
                    }
                    if ui
                        .button(RichText::new(title.trim_end_matches('?')).strong())
                        .clicked()
                    {
                        decision = Some(true);
                    }
                });
            });
        match decision {
            Some(true) => {
                let op = match c {
                    Confirm::Restore(i) => Op::QuarantineRestore {
                        id: i.id.clone(),
                        allow: true,
                    },
                    Confirm::Delete(i) => Op::QuarantineDelete { id: i.id.clone() },
                };
                tasks::service_action(op, self.tx.clone(), self.repaint());
                self.confirm = None;
            }
            Some(false) => self.confirm = None,
            None => {}
        }
    }
}

impl App {
    /// One frame of the whole window.
    fn draw(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        egui::Panel::left("nav")
            .resizable(false)
            .exact_size(190.0)
            .show(ui, |ui| self.nav(ui));
        egui::CentralPanel::default().show(ui, |ui| match self.page {
            Page::Status => self.status_page(ui),
            Page::Scan => self.scan_page(ui),
            Page::Results => self.results_page(ui),
            Page::Update => self.update_page(ui),
            Page::Quarantine => self.quarantine_page(ui),
        });
        self.confirm_window(&ctx);
        if self.running.is_some() || self.updating {
            // Elapsed time and spinners.
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
    }
}

/// Every field of a finding, escaped.
fn details(ui: &mut egui::Ui, f: &Finding) {
    ui.label(
        RichText::new(safe(&f.name))
            .heading()
            .color(severity_color(f.severity)),
    );
    egui::Grid::new("finding-details")
        .num_columns(2)
        .show(ui, |ui| {
            let mut row = |k: &str, v: String| {
                ui.label(RichText::new(k).strong());
                ui.label(v);
                ui.end_row();
            };
            row("Severity", label(&f.severity));
            row(
                "Kind",
                format!("{} (confidence: {})", label(&f.kind), label(&f.confidence)),
            );
            row("Category", label(&f.category));
            row("Target", target_text(&f.target));
            if let Some(h) = target_sha256(&f.target) {
                row("SHA-256", h);
            }
            let mut source = format!(
                "{} {}",
                safe(&f.source.detector),
                safe(&f.source.detector_version)
            );
            if let Some(r) = &f.source.rule_id {
                source.push_str(&format!(", rule {}", safe(r)));
            }
            if let Some(d) = &f.source.database_name {
                source.push_str(&format!(", database \"{}\"", safe(d)));
            }
            row("Source", source);
            row("Recommended", label(&f.recommended_action));
            row("Remediation", label(&f.remediation_status));
        });
    ui.add_space(4.0);
    for e in &f.evidence {
        ui.label(format!("Evidence: {}", safe(&e.summary)));
    }
    ui.label(safe(&f.explanation));
    if let Some(g) = &f.remediation_guidance {
        ui.label(format!("Guidance: {}", safe(g)));
    }
    ui.horizontal(|ui| {
        if let Some(h) = target_sha256(&f.target)
            && ui.small_button("Copy SHA-256").clicked()
        {
            ui.ctx().copy_text(h);
        }
        if ui.small_button("Copy location").clicked() {
            ui.ctx().copy_text(target_text(&f.target));
        }
    });
}

impl eframe::App for App {
    fn logic(&mut self, _ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_events();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Never leave a scanner running after the window closes.
        if let Some(r) = &self.running {
            r.cancel.cancel_local();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use warden_core::{CancellationToken, ScanConfig};
    use warden_engine::Scanner;
    use warden_engine::signatures::{HashSignatureDatabase, HashSignatureDetector};

    /// A real report of a file whose name carries a right-to-left override
    /// (and, where file names allow it, a terminal escape).
    fn hostile_report() -> (tempfile::TempDir, ScanReport) {
        let dir = tempfile::tempdir().unwrap();
        let name = if cfg!(unix) {
            "invoice\u{202E}fdp.exe\u{1b}[31m"
        } else {
            "invoice\u{202E}fdp.exe"
        };
        let content = b"gui test indicator";
        std::fs::write(dir.path().join(name), content).unwrap();
        let hash = warden_engine::hash_file(
            &dir.path().join(name),
            warden_core::SymlinkPolicy::Skip,
            u64::MAX,
            &CancellationToken::new(),
        )
        .unwrap()
        .sha256;
        let db = format!(
            r#"{{"format":"abyssal-warden.hash-signatures","format_version":1,
                "database":{{"name":"gui-test","version":"1"}},
                "signatures":[{{"id":"GUI-1","name":"Test.Name","sha256":"{hash}",
                "category":"test_indicator","severity":"high","rule_version":1}}]}}"#
        );
        let db = HashSignatureDatabase::from_slice(db.as_bytes()).unwrap();
        let mut scanner = Scanner::new(ScanConfig::new(vec![dir.path().to_owned()])).unwrap();
        scanner.add_detector(Box::new(HashSignatureDetector::new(db)));
        let report = scanner.scan(&CancellationToken::new(), |_, _| {}).unwrap();
        assert_eq!(report.findings.len(), 1);
        (dir, report)
    }

    fn texts(shape: &egui::epaint::Shape, out: &mut Vec<String>) {
        match shape {
            egui::epaint::Shape::Text(t) => out.push(t.galley.text().to_owned()),
            egui::epaint::Shape::Vec(v) => v.iter().for_each(|s| texts(s, out)),
            _ => {}
        }
    }

    /// Draws `app` twice (egui lays out in the second frame) and returns
    /// every string that was drawn.
    fn render(ctx: &egui::Context, app: &mut App) -> Vec<String> {
        let mut out = Vec::new();
        for _ in 0..2 {
            let full = ctx.run_ui(egui::RawInput::default(), |ui| app.draw(ui));
            out.clear();
            for s in &full.shapes {
                texts(&s.shape, &mut out);
            }
        }
        out
    }

    #[test]
    fn every_page_renders_and_hostile_text_is_inert() {
        let (_dir, report) = hostile_report();
        let ctx = egui::Context::default();
        let mut app = App::with_context(ctx.clone(), None);
        app.report = Some(report);
        app.selected = Some(0);
        app.service = ServiceState::Connected(ServiceStatus {
            server_version: "0.1.0".into(),
            started_at: time::OffsetDateTime::UNIX_EPOCH,
            running_as_root: true,
            jobs_running: 0,
            jobs_queued: 0,
            schedules: 1,
            caller: "1000".into(),
            caller_is_admin: true,
            last_audit: None,
        });
        let item = QuarantineItem {
            id: "q1".into(),
            state: "quarantined".into(),
            original_path: "/tmp/evil\u{202E}txt.exe".into(),
            sha256: "00".repeat(32),
            reason: "reason\u{1b}]8;;http://x\u{7}".into(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        app.quarantine = Some(Ok(vec![item.clone()]));
        app.schedules = Some(Ok(Vec::new()));

        let mut all = Vec::new();
        for page in [
            Page::Status,
            Page::Scan,
            Page::Results,
            Page::Update,
            Page::Quarantine,
        ] {
            app.page = page;
            all.extend(render(&ctx, &mut app));
        }
        app.page = Page::Quarantine;
        app.confirm = Some(Confirm::Delete(item));
        all.extend(render(&ctx, &mut app));

        // Nothing drawn contains a control or bidi character...
        for t in &all {
            assert!(
                !warden_core::text::has_unsafe_chars(t, true),
                "unsafe text drawn: {t:?}"
            );
        }
        // ...and the hostile names were shown, escaped.
        assert!(
            all.iter().any(|t| t.contains("invoice\\u{202e}fdp.exe")),
            "{all:?}"
        );
        // (Detection names cannot carry such characters: the signature
        // database refuses them at load time.)
        assert!(all.iter().any(|t| t.contains("evil\\u{202e}txt.exe")));
        assert!(all.iter().any(|t| t.contains("Delete file permanently")));
    }
}
