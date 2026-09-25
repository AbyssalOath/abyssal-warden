//! Scheduled jobs. Times are UTC. A run missed while the machine was off
//! starts once, as soon as the service is up; runs never pile up.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration as StdDuration;

use time::{Duration, OffsetDateTime, Time};
use warden_ipc::{JobKind, ScheduleInfo};

use crate::config::{Schedule, ServiceConfig, parse_hhmm};
use crate::jobs::{JobSpec, Manager, RunAs};
use crate::log;
use crate::store::Store;

/// When `s` is next due, given its last run.
pub(crate) fn next_due(
    s: &Schedule,
    last: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> OffsetDateTime {
    let interval = Duration::hours(i64::from(s.every_hours));
    match s.at_utc.as_deref().and_then(parse_hhmm) {
        None => last.map_or(now, |l| l + interval),
        Some((h, m)) => {
            let at = Time::from_hms(h, m, 0).unwrap_or(Time::MIDNIGHT);
            match last {
                Some(l) => (l.date() + Duration::days(i64::from(s.every_hours / 24)))
                    .with_time(at)
                    .assume_utc(),
                None => {
                    let today = now.date().with_time(at).assume_utc();
                    if today >= now {
                        today
                    } else {
                        today + Duration::days(1)
                    }
                }
            }
        }
    }
}

pub(crate) fn info(cfg: &ServiceConfig, store: &Store, now: OffsetDateTime) -> Vec<ScheduleInfo> {
    let state = store.schedule_state();
    cfg.schedules
        .iter()
        .map(|s| {
            let last = state.get(&s.name).copied();
            ScheduleInfo {
                name: s.name.clone(),
                kind: s.kind,
                paths: s.paths.clone(),
                every_hours: s.every_hours,
                at_utc: s.at_utc.clone(),
                heuristics: s.heuristics,
                quarantine: s.quarantine,
                last_run: last,
                next_run: next_due(s, last, now),
            }
        })
        .collect()
}

pub(crate) fn spec(s: &Schedule) -> JobSpec {
    JobSpec {
        kind: s.kind,
        paths: if s.kind == JobKind::Scan {
            s.paths.clone()
        } else {
            Vec::new()
        },
        heuristics: s.heuristics,
        no_archives: false,
        quarantine: s.quarantine,
        run_as: RunAs::Service,
    }
}

/// Starts `s` now and records the run.
pub(crate) fn start(
    s: &Schedule,
    manager: &Manager,
    store: &Store,
) -> Result<uuid::Uuid, warden_ipc::Rejection> {
    let id = manager.submit(crate::service_principal(), Some(s.name.clone()), spec(s))?;
    let mut state = store.schedule_state();
    state.insert(s.name.clone(), OffsetDateTime::now_utc());
    if let Err(e) = store.save_schedule_state(&state) {
        log(&format!("cannot record schedule state: {e}"));
    }
    Ok(id)
}

/// Checks the schedules every 30 seconds until `stop` is set.
pub(crate) fn run(
    cfg: Arc<ServiceConfig>,
    manager: Arc<Manager>,
    store: Arc<Store>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::SeqCst) {
        let now = OffsetDateTime::now_utc();
        let state: BTreeMap<String, OffsetDateTime> = store.schedule_state();
        for s in &cfg.schedules {
            if now >= next_due(s, state.get(&s.name).copied(), now) {
                match start(s, &manager, &store) {
                    Ok(id) => log(&format!("schedule {} started job {id}", s.name)),
                    Err(e) => log(&format!("schedule {} not started: {e}", s.name)),
                }
            }
        }
        for _ in 0..30 {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(StdDuration::from_secs(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn sched(every: u32, at: Option<&str>) -> Schedule {
        Schedule {
            name: "s".into(),
            kind: JobKind::Scan,
            paths: vec!["/x".into()],
            every_hours: every,
            at_utc: at.map(str::to_owned),
            heuristics: false,
            quarantine: false,
        }
    }

    #[test]
    fn interval_schedules() {
        let now = datetime!(2026-09-25 10:00 UTC);
        let s = sched(6, None);
        assert_eq!(next_due(&s, None, now), now, "never run: due now");
        assert_eq!(
            next_due(&s, Some(datetime!(2026-09-25 07:00 UTC)), now),
            datetime!(2026-09-25 13:00 UTC)
        );
        // Missed while off: due immediately, once.
        assert!(next_due(&s, Some(datetime!(2026-09-20 07:00 UTC)), now) <= now);
    }

    #[test]
    fn time_of_day_schedules() {
        let s = sched(24, Some("03:30"));
        assert_eq!(
            next_due(&s, None, datetime!(2026-09-25 02:00 UTC)),
            datetime!(2026-09-25 03:30 UTC)
        );
        assert_eq!(
            next_due(&s, None, datetime!(2026-09-25 04:00 UTC)),
            datetime!(2026-09-26 03:30 UTC)
        );
        assert_eq!(
            next_due(
                &s,
                Some(datetime!(2026-09-25 03:30:05 UTC)),
                datetime!(2026-09-25 04:00 UTC)
            ),
            datetime!(2026-09-26 03:30 UTC)
        );
        let weekly = sched(168, Some("01:00"));
        assert_eq!(
            next_due(
                &weekly,
                Some(datetime!(2026-09-25 01:00 UTC)),
                datetime!(2026-09-26 00:00 UTC)
            ),
            datetime!(2026-10-02 01:00 UTC)
        );
    }
}
