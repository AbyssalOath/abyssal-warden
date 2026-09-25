//! `abyssal-warden` command-line interface.
//!
//! Exit codes (see `docs/user/scanning.md`):
//! * 0 - scan completed, no findings, every entry processed
//! * 1 - one or more findings
//! * 2 - usage, configuration or fatal error
//! * 3 - no findings, but some entries could not be scanned
//! * 130 - cancelled

mod content;
mod output;
mod quarantine;

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand, ValueEnum};
use warden_core::{
    CancellationToken, Detector, ScanConfig, ScanLimits, ScanReport, ScanStats, ScanStatus,
    SymlinkPolicy,
};
use warden_engine::{HashFileError, ProgressEvent, Scanner, hash_file};

const EXIT_FINDINGS: u8 = 1;
pub(crate) const EXIT_ERROR: u8 = 2;
const EXIT_INCOMPLETE: u8 = 3;
const EXIT_CANCELLED: u8 = 130;

#[derive(Parser, Debug)]
#[command(
    name = "abyssal-warden",
    version,
    about = "Abyssal Warden: open-source malware scanning (early development; see known limitations)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan files and directories.
    Scan(ScanArgs),
    /// Print the SHA-256 of files (same hardened reader as `scan`).
    Hash(HashArgs),
    /// Work with signature databases.
    #[command(subcommand)]
    Signatures(SignaturesCommand),
    /// Work with YARA rules.
    #[command(subcommand)]
    Yara(YaraCommand),
    /// Quarantine, restore and delete files (Linux only).
    Quarantine(quarantine::QuarantineArgs),
}

#[derive(Args, Debug)]
struct ScanArgs {
    /// Files or directories to scan.
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    /// Hash signature database (JSON). May be given more than once.
    #[arg(short = 's', long = "signatures", value_name = "FILE")]
    signatures: Vec<PathBuf>,
    /// YARA rule file, or directory of *.yar/*.yara files. May be given more
    /// than once.
    #[arg(short = 'y', long = "yara", value_name = "PATH")]
    yara: Vec<PathBuf>,
    #[command(flatten)]
    trust: content::TrustArgs,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,
    /// Write the report to FILE instead of standard output.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Follow symbolic links below the scan paths (may leave the scan paths).
    #[arg(long)]
    follow_symlinks: bool,
    /// Skip files larger than SIZE (bytes; K, M and G suffixes are powers of 1024).
    #[arg(long, value_name = "SIZE", default_value = "512M", value_parser = parse_size)]
    max_file_size: u64,
    /// Largest file whose content is inspected by YARA; larger files are
    /// still hashed and reported as not content-inspected.
    #[arg(long, value_name = "SIZE", default_value = "64M", value_parser = parse_size)]
    max_content_size: u64,
    /// Time limit per file, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = ScanLimits::DEFAULT_FILE_TIMEOUT_MS / 1000,
          value_parser = clap::value_parser!(u64).range(1..=86_400))]
    file_timeout: u64,
    /// Maximum directory depth below each scan path.
    #[arg(long, value_name = "N", default_value_t = ScanLimits::DEFAULT_MAX_DEPTH)]
    max_depth: usize,
    /// Number of worker threads [default: available CPUs, at most 8].
    #[arg(long, value_name = "N")]
    threads: Option<usize>,
    /// Exclude a path (and everything below it). May be given more than once.
    #[arg(long = "exclude", value_name = "PATH")]
    excludes: Vec<PathBuf>,
    /// Do not apply the platform's default excludes (Linux: /proc, /sys).
    #[arg(long)]
    no_default_excludes: bool,
    /// Do not cross into other filesystems/volumes.
    #[arg(long)]
    one_file_system: bool,
    /// Never show the progress line.
    #[arg(long)]
    no_progress: bool,
    /// List skipped entries in human-readable output.
    #[arg(long)]
    show_skipped: bool,
    /// After the scan, quarantine files with confirmed malware matches
    /// (exact-hash known indicators categorised as malware, outside system
    /// directories). Nothing else is ever remediated automatically.
    #[arg(long)]
    quarantine: bool,
    /// Quarantine store for --quarantine.
    #[arg(long, value_name = "DIR", requires = "quarantine")]
    quarantine_store: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    Human,
    Json,
}

#[derive(Args, Debug)]
struct HashArgs {
    #[arg(required = true)]
    files: Vec<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum SignaturesCommand {
    /// Validate a hash signature database (and its signature) and print a summary.
    Validate {
        file: PathBuf,
        #[command(flatten)]
        trust: content::TrustArgs,
    },
}

#[derive(Subcommand, Debug)]
enum YaraCommand {
    /// Compile YARA rules (and check their signatures) and print a summary.
    Validate {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[command(flatten)]
        trust: content::TrustArgs,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => run_scan(args),
        Command::Hash(args) => run_hash(&args),
        Command::Signatures(SignaturesCommand::Validate { file, trust }) => {
            run_validate(&file, &trust)
        }
        Command::Yara(YaraCommand::Validate { paths, trust }) => run_yara_validate(&paths, &trust),
        Command::Quarantine(args) => quarantine::run(args),
    }
}

fn run_scan(args: ScanArgs) -> ExitCode {
    // Any failure to load or verify content aborts: never scan with a
    // silently reduced detector set.
    let detectors = match load_detectors(&args) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {}", output::sanitize(&e));
            return ExitCode::from(EXIT_ERROR);
        }
    };

    let mut config = ScanConfig::new(args.paths.clone());
    config.excludes = args.excludes.clone();
    if !args.no_default_excludes {
        config.excludes.extend(default_excludes(&args.paths));
    }
    config.symlink_policy = if args.follow_symlinks {
        SymlinkPolicy::Follow
    } else {
        SymlinkPolicy::Skip
    };
    config.same_file_system = args.one_file_system;
    config.limits.max_file_size = args.max_file_size;
    config.limits.max_depth = args.max_depth;
    config.limits.max_content_size = args.max_content_size;
    config.limits.file_timeout_ms = args.file_timeout * 1000;
    if let Some(n) = args.threads {
        config.workers = n;
    }

    let mut scanner = match Scanner::new(config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    };
    for d in detectors {
        scanner.add_detector(d);
    }
    if scanner.detectors().is_empty() {
        eprintln!(
            "warning: no signature database or YARA rules given (--signatures, --yara); files \
             will be hashed but NOT evaluated for threats"
        );
    }

    let token = CancellationToken::new();
    install_interrupt_handler(&token);

    let show_progress = !args.no_progress && io::stderr().is_terminal();
    let mut progress = ProgressLine::new(show_progress);
    let result = scanner.scan(&token, |ev, stats| progress.update(ev, stats));
    progress.clear();

    let mut report = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    };
    if args.quarantine {
        if report.status == ScanStatus::Completed {
            quarantine::remediate_report(
                &mut report,
                args.quarantine_store.as_deref(),
                args.max_file_size,
            );
        } else {
            eprintln!("warning: the scan did not complete; nothing was quarantined");
        }
    }

    let rendered = match args.format {
        Format::Json => match serde_json::to_string_pretty(&report) {
            Ok(mut s) => {
                s.push('\n');
                s
            }
            Err(e) => {
                eprintln!("error: cannot serialise report: {e}");
                return ExitCode::from(EXIT_ERROR);
            }
        },
        Format::Human => output::render_human(&report, args.show_skipped),
    };

    let written = match &args.output {
        Some(path) => write_atomically(path, rendered.as_bytes()),
        None => io::stdout().lock().write_all(rendered.as_bytes()),
    };
    if let Err(e) = written {
        eprintln!("error: cannot write report: {e}");
        return ExitCode::from(EXIT_ERROR);
    }

    ExitCode::from(exit_code(&report))
}

fn exit_code(report: &ScanReport) -> u8 {
    if report.status == ScanStatus::Cancelled {
        EXIT_CANCELLED
    } else if report.stats.findings > 0 {
        EXIT_FINDINGS
    } else if !report.is_complete() {
        EXIT_INCOMPLETE
    } else {
        0
    }
}

/// Pseudo-filesystems whose "files" are kernel interfaces, not stored data.
/// A default exclude is dropped if the user asked to scan inside it.
fn default_excludes(roots: &[PathBuf]) -> Vec<PathBuf> {
    let candidates: &[&str] = if cfg!(target_os = "linux") {
        &["/proc", "/sys"]
    } else {
        &[]
    };
    candidates
        .iter()
        .map(PathBuf::from)
        .filter(|ex| {
            !roots.iter().any(|r| {
                std::path::absolute(r)
                    .map(|abs| abs.starts_with(ex))
                    .unwrap_or(false)
            })
        })
        .collect()
}

fn install_interrupt_handler(token: &CancellationToken) {
    let token = token.clone();
    let result = ctrlc::set_handler(move || {
        if token.is_cancelled() {
            // Second interrupt: the user wants out now.
            std::process::exit(i32::from(EXIT_CANCELLED));
        }
        token.cancel();
        eprintln!("\ncancelling; press Ctrl-C again to exit immediately");
    });
    if let Err(e) = result {
        eprintln!(
            "warning: cannot install interrupt handler ({e}); Ctrl-C will not cancel cleanly"
        );
    }
}

/// Write via a temporary file in the destination directory, then rename.
/// The rename replaces a symlink at `path` rather than writing through it,
/// and readers never see a partially written report.
fn write_atomically(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

struct ProgressLine {
    enabled: bool,
    last: Option<Instant>,
    drawn: bool,
}

impl ProgressLine {
    const INTERVAL: Duration = Duration::from_millis(100);

    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            last: None,
            drawn: false,
        }
    }

    fn update(&mut self, event: &ProgressEvent<'_>, stats: &ScanStats) {
        if !self.enabled {
            return;
        }
        let due = self.last.is_none_or(|t| t.elapsed() >= Self::INTERVAL);
        if !due && !matches!(event, ProgressEvent::Finding(_)) {
            return;
        }
        self.last = Some(Instant::now());
        self.drawn = true;
        // Paths are deliberately not shown: they are attacker-controlled and
        // would need escaping and truncation on every redraw.
        eprint!(
            "\r\x1b[2Kscanned {} files ({}), {} findings, {} skipped, {} issues",
            stats.files_scanned,
            output::human_bytes(stats.bytes_scanned),
            stats.findings,
            stats.entries_skipped,
            stats.issues
        );
    }

    fn clear(&mut self) {
        if self.drawn {
            eprint!("\r\x1b[2K");
            self.drawn = false;
        }
    }
}

fn run_hash(args: &HashArgs) -> ExitCode {
    let token = CancellationToken::new();
    let mut failed = false;
    let mut out = io::stdout().lock();
    for path in &args.files {
        let shown = output::sanitize(&path.to_string_lossy());
        // Explicitly named files are followed if they are links.
        match hash_file(path, SymlinkPolicy::Follow, u64::MAX, &token) {
            Ok(h) => {
                if writeln!(out, "{}  {shown}", h.sha256).is_err() {
                    return ExitCode::from(EXIT_ERROR);
                }
            }
            Err(HashFileError::Skipped(reason)) => {
                failed = true;
                eprintln!("{shown}: not hashed ({})", output::label(&reason));
            }
            Err(e) => {
                failed = true;
                eprintln!("{shown}: {e}");
            }
        }
    }
    if failed {
        ExitCode::from(EXIT_ERROR)
    } else {
        ExitCode::SUCCESS
    }
}

fn load_detectors(args: &ScanArgs) -> Result<Vec<Box<dyn Detector>>, String> {
    let trust = content::Trust::from_args(&args.trust)?;
    let mut detectors: Vec<Box<dyn Detector>> = Vec::new();
    for path in &args.signatures {
        detectors.push(Box::new(content::load_hash_db(path, &trust)?));
    }
    if !args.yara.is_empty() {
        detectors.push(Box::new(content::load_yara(&args.yara, &trust)?));
    }
    Ok(detectors)
}

fn signer_text(db: Option<&warden_core::DatabaseInfo>) -> String {
    match db.and_then(|d| d.signer.as_deref()) {
        Some(k) => format!("signed by key {}", output::sanitize(k)),
        None => "UNSIGNED".to_owned(),
    }
}

fn run_validate(path: &Path, trust: &content::TrustArgs) -> ExitCode {
    let result = content::Trust::from_args(trust).and_then(|t| content::load_hash_db(path, &t));
    match result {
        Ok(det) => {
            let db = det.database();
            let m = db.meta();
            println!(
                "valid: \"{}\" version {} with {} signature(s), {}",
                output::sanitize(&m.name),
                output::sanitize(&m.version),
                db.len(),
                signer_text(det.info().database.as_ref())
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("invalid: {}", output::sanitize(&e));
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run_yara_validate(paths: &[PathBuf], trust: &content::TrustArgs) -> ExitCode {
    let result = content::Trust::from_args(trust).and_then(|t| content::load_yara(paths, &t));
    match result {
        Ok(det) => {
            println!(
                "valid: {} YARA rule(s), {}",
                det.rule_count(),
                signer_text(det.info().database.as_ref())
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("invalid: {}", output::sanitize(&e));
            ExitCode::from(EXIT_ERROR)
        }
    }
}

/// Parse a size such as `4096`, `64K`, `512M` or `2G` (binary multiples).
pub(crate) fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (digits, multiplier) = match s.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => {
            let m: u64 = match c.to_ascii_uppercase() {
                'K' => 1 << 10,
                'M' => 1 << 20,
                'G' => 1 << 30,
                'T' => 1 << 40,
                _ => return Err(format!("unknown size suffix `{c}` (use K, M, G or T)")),
            };
            (&s[..i], m)
        }
        _ => (s, 1),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("`{s}` is not a size (e.g. 4096, 64K, 512M, 2G)"))?;
    let bytes = n
        .checked_mul(multiplier)
        .ok_or_else(|| format!("`{s}` is too large"))?;
    if bytes == 0 {
        return Err("size must be greater than zero".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sizes() {
        assert_eq!(parse_size("4096"), Ok(4096));
        assert_eq!(parse_size("64K"), Ok(64 * 1024));
        assert_eq!(parse_size("512m"), Ok(512 * 1024 * 1024));
        assert_eq!(parse_size("2G"), Ok(2 * 1024 * 1024 * 1024));
        assert!(parse_size("").is_err());
        assert!(parse_size("0").is_err());
        assert!(parse_size("-1").is_err());
        assert!(parse_size("12Q").is_err());
        assert!(parse_size("K").is_err());
        assert!(parse_size("99999999999T").is_err());
        assert!(parse_size("1é").is_err());
    }

    #[test]
    fn cli_definition_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn default_excludes_yield_to_explicit_roots() {
        let ex = default_excludes(&[PathBuf::from("/")]);
        assert_eq!(ex, vec![PathBuf::from("/proc"), PathBuf::from("/sys")]);
        let ex = default_excludes(&[PathBuf::from("/proc/1")]);
        assert_eq!(ex, vec![PathBuf::from("/sys")]);
    }
}
