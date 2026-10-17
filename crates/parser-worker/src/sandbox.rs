//! Resource limits and the Linux seccomp filter (ADR 0002). Every failure is
//! returned so the worker refuses to start rather than run unsandboxed.
//! macOS and Windows dev builds have no filter (issue #23, out of scope).
use std::io;

pub struct WorkerLimits {
    pub memory_mib: u64,
    /// CPU seconds allowed for each job.
    pub cpu_secs: u64,
    pub max_jobs: u64,
}

impl WorkerLimits {
    pub fn from_env() -> Self {
        let read = |name: &str, default: u64| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        };
        Self {
            memory_mib: read("CURRAWONG_WORKER_AS_MIB", 512),
            cpu_secs: read("CURRAWONG_WORKER_CPU_SECS", 30).max(1),
            max_jobs: read("CURRAWONG_WORKER_MAX_JOBS", 500).max(1),
        }
    }
}

/// Address space for the process. CPU gets a hard cap over the worker's
/// life (`cpu_secs * max_jobs`); [`start_job`] sets the per-job soft limit.
pub fn apply_limits(limits: &WorkerLimits) -> io::Result<()> {
    let bytes = limits.memory_mib.saturating_mul(1024 * 1024);
    lower(rlimit::Resource::AS, bytes, bytes)?;
    let hard = limits
        .cpu_secs
        .saturating_mul(limits.max_jobs.saturating_add(1));
    lower(rlimit::Resource::CPU, limits.cpu_secs, hard)
}

/// Never asks for more than the current hard limit, which would need privilege.
fn lower(resource: rlimit::Resource, soft: u64, hard: u64) -> io::Result<()> {
    let (_, current) = rlimit::getrlimit(resource)?;
    let hard = hard.min(current);
    tolerate_unsupported(rlimit::setrlimit(resource, soft.min(hard), hard))
}

/// Gives the next job `cpu_secs` on top of the CPU already used, so a long
/// lived worker is not killed half way through innocent mail.
pub fn start_job(limits: &WorkerLimits) -> io::Result<()> {
    let (_, hard) = rlimit::getrlimit(rlimit::Resource::CPU)?;
    let soft = job_cpu_limit(cpu_used_secs(), limits.cpu_secs, hard);
    tolerate_unsupported(rlimit::setrlimit(rlimit::Resource::CPU, soft, hard))
}

pub fn job_cpu_limit(used_secs: u64, per_job: u64, hard: u64) -> u64 {
    used_secs.saturating_add(per_job).min(hard)
}

/// macOS rejects `RLIMIT_AS`. That is a dev platform, not a deployment one.
fn tolerate_unsupported(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(err) if err.kind() == io::ErrorKind::InvalidInput && !cfg!(target_os = "linux") => {
            Ok(())
        }
        other => other,
    }
}

#[cfg(unix)]
fn cpu_used_secs() -> u64 {
    // SAFETY: getrusage writes into the zeroed struct we own.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    let secs = usage.ru_utime.tv_sec + usage.ru_stime.tv_sec;
    // Round up so a partly used second still counts.
    (secs.max(0) as u64).saturating_add(1)
}

#[cfg(not(unix))]
fn cpu_used_secs() -> u64 {
    0
}

/// Installs the seccomp filter on every thread of the process.
#[cfg(target_os = "linux")]
pub fn install() -> Result<(), String> {
    linux::install()
}

/// No sandbox on this platform. Workers here are for development only.
#[cfg(not(target_os = "linux"))]
pub fn install() -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;

    /// Network, process creation and inspection, kernel attack surface
    /// (io_uring, bpf, perf, userfaultfd, keyrings) and namespace changes.
    /// Each returns EPERM.
    const DENIED: &[i64] = &[
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_chroot,
        libc::SYS_pivot_root,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_personality,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
    ];

    pub fn install() -> Result<(), String> {
        let arch = match std::env::consts::ARCH {
            "x86_64" => TargetArch::x86_64,
            "aarch64" => TargetArch::aarch64,
            other => return Err(format!("no seccomp filter for architecture {other}")),
        };
        let rules = DENIED
            .iter()
            .map(|nr| (*nr, Vec::new()))
            .collect::<BTreeMap<_, _>>();
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            arch,
        )
        .map_err(|err| format!("build seccomp filter: {err}"))?;
        let program: seccompiler::BpfProgram = filter
            .try_into()
            .map_err(|err| format!("compile seccomp filter: {err}"))?;
        seccompiler::apply_filter_all_threads(&program)
            .map_err(|err| format!("apply seccomp filter: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::job_cpu_limit;

    #[test]
    fn each_job_gets_its_own_cpu_allowance() {
        // 500 jobs into a worker's life, the next job still gets 30 s.
        assert_eq!(job_cpu_limit(400, 30, 15_030), 430);
        assert_eq!(job_cpu_limit(15_020, 30, 15_030), 15_030);
    }
}
