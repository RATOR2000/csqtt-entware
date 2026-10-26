// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Root-only, identity-free deadline for a fixed recovery step and its children.

#[cfg(target_os = "linux")]
mod linux {
    use std::{process::{Child, Command, Stdio}, sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant}};
    use std::os::unix::process::CommandExt;

    static STOP: AtomicBool = AtomicBool::new(false);
    extern "C" fn stopped(_: libc::c_int) { STOP.store(true, Ordering::Relaxed); }

    fn owner_current(owner: &(u32, String)) -> bool {
        std::fs::read_to_string(format!("/proc/{}/stat", owner.0)).ok()
            .and_then(|s| s.rsplit_once(')').map(|(_, f)| f.to_owned()))
            .and_then(|s| s.split_whitespace().nth(19).map(str::to_owned))
            .is_some_and(|ticks| ticks == owner.1)
    }

    fn terminate(child: &mut Child) -> Option<std::process::ExitStatus> {
        // The still-owned direct child created this independent process group.
        // Never target the monitor, procd or a daemon PID taken from status.
        let group = -(child.id() as libc::pid_t);
        unsafe { libc::kill(group, libc::SIGTERM); }
        std::thread::sleep(Duration::from_millis(200));
        unsafe { libc::kill(group, libc::SIGKILL); }
        child.wait().ok()
    }

    fn exited_without_reaping(child: &Child) -> Result<bool, ()> {
        // Keep the group leader's PID reserved until descendants are stopped.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::waitid(libc::P_PID, child.id(), &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) };
        if result == 0 { Ok(unsafe { info.si_pid() } != 0) } else { Err(()) }
    }

    fn bounded(mut command: Command, limit: Duration, owner: Option<(u32, String)>) -> bool {
        command.process_group(0).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        let Ok(mut child) = command.spawn() else { return false; };
        let start = Instant::now();
        loop {
            match exited_without_reaping(&child) {
                Ok(true) => return terminate(&mut child).is_some_and(|status| status.success()),
                Err(_) => { let _ = terminate(&mut child); return false; }
                _ => {}
            }
            if start.elapsed() >= limit || STOP.load(Ordering::Relaxed) ||
                owner.as_ref().is_some_and(|o| !owner_current(o)) {
                let _ = terminate(&mut child); return false;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    pub(super) fn run(action: &str) -> i32 {
        if unsafe { libc::geteuid() } != 0 || !matches!(action, "soft" | "transport") { return 2; }
        let owner = std::env::var("CSQTT_OPERATION_OWNER").ok().and_then(|v| v.parse::<u32>().ok());
        let ticks = std::env::var("CSQTT_OPERATION_TICKS").ok();
        let Some(owner) = owner.zip(ticks) else { return 2; };
        if !owner_current(&owner) { return 2; }
        STOP.store(false, Ordering::Relaxed);
        unsafe {
            libc::signal(libc::SIGTERM, stopped as *const () as libc::sighandler_t);
            libc::signal(libc::SIGINT, stopped as *const () as libc::sighandler_t);
            libc::signal(libc::SIGHUP, stopped as *const () as libc::sighandler_t);
        }
        let remaining = std::env::var("CSQTT_RECOVERY_DEADLINE_BOOTTIME_MS").ok()
            .and_then(|v| v.parse::<u64>().ok())
            .and_then(|deadline| deadline.checked_sub(crate::daemon::boottime_ms()));
        let Some(remaining) = remaining.filter(|v| *v > 0) else { return 2; };
        let mut command = Command::new("/usr/libexec/csqtt/manage");
        command.arg("recovery-step").arg(action);
        if bounded(command, Duration::from_millis(remaining.min(70_000)), Some(owner)) { 0 } else { 1 }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn deadline_kills_owned_descendants_and_preserves_an_unrelated_child() {
            let mut unrelated = Command::new("/bin/sleep").arg("30").spawn().unwrap();
            let mut command = Command::new("/bin/sh");
            command.arg("-c").arg("sleep 30 & wait");
            let start = Instant::now();
            assert!(!bounded(command, Duration::from_millis(100), None));
            assert!(start.elapsed() < Duration::from_secs(3));
            assert!(unrelated.try_wait().unwrap().is_none());
            unrelated.kill().unwrap(); unrelated.wait().unwrap();
        }
        #[test]
        fn normal_completion_preserves_the_exit_result() {
            assert!(bounded(Command::new("/bin/true"), Duration::from_secs(2), None));
            assert!(!bounded(Command::new("/bin/false"), Duration::from_secs(2), None));
        }
        #[test]
        fn an_exited_leader_does_not_leave_its_child_running() {
            let path = std::env::temp_dir().join(format!("csqtt-group-{}", uuid::Uuid::new_v4()));
            let mut command = Command::new("/bin/sh");
            command.arg("-c").arg("sleep 30 & echo $! > \"$PID_OUTPUT\"; exit 0").env("PID_OUTPUT", &path);
            assert!(bounded(command, Duration::from_secs(2), None));
            let pid: u32 = std::fs::read_to_string(&path).unwrap().trim().parse().unwrap();
            let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()
                .and_then(|s| s.rsplit_once(')').map(|(_, f)| f.trim().chars().next().unwrap()));
            assert!(state.is_none() || matches!(state, Some('Z' | 'X')));
            std::fs::remove_file(path).unwrap();
        }
    }
}

pub fn run_cli(action: &str) -> i32 {
    #[cfg(target_os = "linux")] { linux::run(action) }
    #[cfg(not(target_os = "linux"))] { let _ = action; 2 }
}
