//! Resource limits, Landlock and the seccomp filter (ADR 0002). Every failure
//! is returned so the worker refuses to start rather than run unsandboxed.
//! macOS and Windows dev builds have neither (issue #23, out of scope).
//!
//! The worker may only read `<dir>/in` and write `<dir>/out`, where `<dir>` is
//! the private directory the supervisor made for it (`CURRAWONG_WORKER_DIR`).
use std::io;
use std::path::PathBuf;

pub struct WorkerLimits {
    pub memory_mib: u64,
    /// CPU seconds allowed for each job.
    pub cpu_secs: u64,
    pub max_jobs: u64,
    /// Process limit, set only when the worker runs under its own uid
    /// (RLIMIT_NPROC counts every process of the uid).
    pub nproc: Option<u64>,
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

impl WorkerLimits {
    pub fn from_env() -> Self {
        Self {
            memory_mib: env_u64("CURRAWONG_WORKER_AS_MIB").unwrap_or(512),
            cpu_secs: env_u64("CURRAWONG_WORKER_CPU_SECS").unwrap_or(30).max(1),
            max_jobs: env_u64("CURRAWONG_WORKER_MAX_JOBS").unwrap_or(500).max(1),
            nproc: env_u64("CURRAWONG_WORKER_NPROC"),
        }
    }
}

pub struct SandboxConfig {
    pub dir: Option<PathBuf>,
    pub landlock_required: bool,
}

impl SandboxConfig {
    pub fn from_env() -> Self {
        Self {
            dir: std::env::var_os("CURRAWONG_WORKER_DIR").map(PathBuf::from),
            landlock_required: std::env::var("CURRAWONG_WORKER_LANDLOCK").as_deref()
                != Ok("optional"),
        }
    }
}

/// Closes every descriptor above stderr. Runs before anything else opens one.
pub fn close_inherited_fds() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range only closes descriptors; nothing else is open yet.
        let rc = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
        if rc == 0 {
            return;
        }
    }
    #[cfg(unix)]
    for fd in 3..1024 {
        // SAFETY: as above; EBADF for descriptors that are not open.
        unsafe { libc::close(fd) };
    }
}

/// glibc gives each thread that allocates its own malloc arena, up to eight
/// per CPU, and each reserves 64 MiB of address space it never gives back.
/// Under `RLIMIT_AS` that took the limit away from parsing whenever tokio's
/// blocking pool happened to start another thread. The worker parses on one
/// thread, so one arena costs nothing. Call before any thread is started.
pub fn one_malloc_arena() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: sets an allocator parameter; no other thread exists yet.
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, 1);
    }
}

/// Address space, no core files, a file size cap and, under a dedicated uid,
/// a process cap. CPU gets a hard cap over the worker's life
/// (`cpu_secs * max_jobs`); [`start_job`] sets the per-job soft limit.
pub fn apply_limits(limits: &WorkerLimits) -> io::Result<()> {
    let bytes = limits.memory_mib.saturating_mul(1024 * 1024);
    lower(rlimit::Resource::AS, bytes, bytes)?;
    lower(rlimit::Resource::CORE, 0, 0)?;
    // No single extracted part can be bigger than the memory that held it.
    lower(rlimit::Resource::FSIZE, bytes, bytes)?;
    if let Some(nproc) = limits.nproc {
        lower(rlimit::Resource::NPROC, nproc, nproc)?;
    }
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

/// Not dumpable, Landlock, then seccomp on every thread. Returns warnings
/// (Landlock not enforced when the operator allowed that).
#[cfg(target_os = "linux")]
pub fn install(cfg: &SandboxConfig) -> Result<Vec<String>, String> {
    linux::install(cfg)
}

/// No sandbox on this platform. Workers here are for development only.
#[cfg(not(target_os = "linux"))]
pub fn install(_cfg: &SandboxConfig) -> Result<Vec<String>, String> {
    Ok(Vec::new())
}

/// Tries what a compromised worker would try and reports the errno of each
/// attempt (0 means it worked). Used by `currawong-parser-worker --probe`.
#[cfg(target_os = "linux")]
pub fn probe(cfg: &SandboxConfig) -> Vec<(&'static str, i32)> {
    linux::probe(cfg)
}

#[cfg(not(target_os = "linux"))]
pub fn probe(_cfg: &SandboxConfig) -> Vec<(&'static str, i32)> {
    Vec::new()
}

#[cfg(target_os = "linux")]
mod linux {
    use super::SandboxConfig;
    use std::path::Path;

    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
    /// x32 system calls on x86_64 carry this bit; none are allowed.
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    /// CLONE_NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET.
    const CLONE_NAMESPACES: u32 = 0x7e02_0000;

    /// Network, process creation and inspection, signals to other
    /// processes, kernel attack surface (io_uring, bpf, perf, userfaultfd,
    /// keyrings), mounts, namespaces and identity changes. Each is EPERM.
    const DENIED: &[libc::c_long] = &[
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_process_madvise,
        libc::SYS_kcmp,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
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
        libc::SYS_mount_setattr,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_fspick,
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
        libc::SYS_fanotify_init,
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setreuid,
        libc::SYS_setregid,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_setgroups,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_fork,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_vfork,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_iopl,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_ioperm,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_modify_ldt,
    ];

    pub fn install(cfg: &SandboxConfig) -> Result<Vec<String>, String> {
        let mut warnings = Vec::new();
        // Other processes of this uid cannot ptrace it or read its memory.
        // SAFETY: plain prctl with constant arguments.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(format!(
                "PR_SET_DUMPABLE: {}",
                std::io::Error::last_os_error()
            ));
        }
        let dir = cfg
            .dir
            .as_deref()
            .ok_or("CURRAWONG_WORKER_DIR is not set")?;
        if let Some(warning) = landlock(dir, cfg.landlock_required)? {
            warnings.push(warning);
        }
        seccomp()?;
        Ok(warnings)
    }

    fn landlock(dir: &Path, required: bool) -> Result<Option<String>, String> {
        use ::landlock::{
            Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
            RulesetStatus, ABI,
        };
        let abi = ABI::V5;
        let fd = |name: &str| {
            PathFd::new(dir.join(name)).map_err(|err| format!("landlock {name}: {err}"))
        };
        let (input, output) = (fd("in")?, fd("out")?);
        let status = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .and_then(|ruleset| ruleset.create())
            .and_then(|ruleset| ruleset.add_rule(PathBeneath::new(input, AccessFs::from_read(abi))))
            .and_then(|ruleset| ruleset.add_rule(PathBeneath::new(output, AccessFs::from_all(abi))))
            .and_then(|ruleset| ruleset.restrict_self())
            .map_err(|err| format!("landlock: {err}"))?;
        match status.ruleset {
            RulesetStatus::NotEnforced if required => Err(
                "Landlock is not available on this kernel (set scanner.require_landlock = false \
                 to run workers without filesystem confinement)"
                    .into(),
            ),
            RulesetStatus::NotEnforced => Ok(Some(
                "Landlock is not available: the parser worker can read any file this user can"
                    .into(),
            )),
            _ => Ok(None),
        }
    }

    fn seccomp() -> Result<(), String> {
        let program = filter()?;
        let prog = libc::sock_fprog {
            len: program.len() as u16,
            filter: program.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: the kernel copies the program; it outlives the call.
        let rc = unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                -1
            } else {
                libc::syscall(
                    libc::SYS_seccomp,
                    libc::SECCOMP_SET_MODE_FILTER,
                    libc::SECCOMP_FILTER_FLAG_TSYNC,
                    &prog as *const libc::sock_fprog,
                )
            }
        };
        match rc {
            0 => Ok(()),
            n if n > 0 => Err(format!("seccomp: thread {n} could not be synchronised")),
            _ => Err(format!("seccomp: {}", std::io::Error::last_os_error())),
        }
    }

    fn stmt(code: u32, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn jump(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        }
    }

    fn errno(value: i32) -> libc::sock_filter {
        stmt(
            libc::BPF_RET | libc::BPF_K,
            libc::SECCOMP_RET_ERRNO | (value as u32 & libc::SECCOMP_RET_DATA),
        )
    }

    /// The BPF program. Wrong architecture kills the process.
    pub(super) fn filter() -> Result<Vec<libc::sock_filter>, String> {
        let arch = match std::env::consts::ARCH {
            "x86_64" => AUDIT_ARCH_X86_64,
            "aarch64" => AUDIT_ARCH_AARCH64,
            other => return Err(format!("no seccomp filter for architecture {other}")),
        };
        let ld = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
        let jeq = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
        let mut p = vec![
            stmt(ld, 4), // seccomp_data.arch
            jump(jeq, arch, 1, 0),
            stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_KILL_PROCESS),
            stmt(ld, 0), // seccomp_data.nr
        ];
        if arch == AUDIT_ARCH_X86_64 {
            p.push(jump(
                libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K,
                X32_SYSCALL_BIT,
                0,
                1,
            ));
            p.push(errno(libc::EPERM));
        }
        for nr in DENIED {
            p.push(jump(jeq, *nr as u32, 0, 1));
            p.push(errno(libc::EPERM));
        }
        // glibc falls back to clone when clone3 is missing; clone flags can
        // be checked, clone3's are behind a pointer.
        p.push(jump(jeq, libc::SYS_clone3 as u32, 0, 1));
        p.push(errno(libc::ENOSYS));
        p.push(jump(jeq, libc::SYS_clone as u32, 0, 3));
        p.push(stmt(ld, 16)); // low half of args[0], the flags
        p.push(jump(
            libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K,
            CLONE_NAMESPACES,
            0,
            1,
        ));
        p.push(errno(libc::EPERM));
        p.push(stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW));
        Ok(p)
    }

    fn errno_of(rc: i64) -> i32 {
        if rc < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        } else {
            0
        }
    }

    fn try_open(path: &Path, flags: i32) -> i32 {
        let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
            return -1;
        };
        // SAFETY: valid C string; the descriptor is closed straight away.
        let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
        let err = errno_of(fd as i64);
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        err
    }

    pub fn probe(cfg: &SandboxConfig) -> Vec<(&'static str, i32)> {
        let dir = cfg.dir.clone().unwrap_or_default();
        // SAFETY: getppid cannot fail.
        let ppid = unsafe { libc::getppid() };
        let mut out = Vec::new();
        // SAFETY (all syscalls below): constant or checked arguments; any
        // descriptor or child that does get through is closed or exits.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            out.push(("socket_inet", errno_of(fd as i64)));
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            out.push(("socket_unix", errno_of(fd as i64)));
            let rc = libc::syscall(libc::SYS_pidfd_open, ppid, 0);
            out.push(("pidfd_open", errno_of(rc)));
            let rc = libc::syscall(libc::SYS_pidfd_getfd, 0, 0, 0);
            out.push(("pidfd_getfd", errno_of(rc)));
            let rc = libc::ptrace(libc::PTRACE_ATTACH, ppid, 0, 0);
            out.push(("ptrace", errno_of(rc)));
            let rc = libc::kill(ppid, 0);
            out.push(("kill", errno_of(rc as i64)));
            let rc = libc::syscall(libc::SYS_tgkill, ppid, ppid, 0);
            out.push(("tgkill", errno_of(rc)));
            let args = [c"/bin/true".as_ptr(), std::ptr::null()];
            let rc = libc::execve(args[0], args.as_ptr(), std::ptr::null());
            out.push(("execve", errno_of(rc as i64)));
            let rc = libc::syscall(
                libc::SYS_clone,
                (libc::CLONE_NEWUSER | libc::SIGCHLD) as libc::c_ulong,
                0,
                0,
                0,
                0,
            );
            if rc == 0 {
                libc::_exit(0);
            }
            out.push(("clone_newuser", errno_of(rc)));
            let rc = libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0);
            out.push(("clone3", errno_of(rc)));
            let rc = libc::unshare(libc::CLONE_NEWUSER);
            out.push(("unshare", errno_of(rc as i64)));
            #[cfg(target_arch = "x86_64")]
            {
                let rc = libc::syscall(X32_SYSCALL_BIT as libc::c_long | libc::SYS_getpid);
                out.push(("x32_getpid", errno_of(rc)));
            }
        }
        let mem = std::path::PathBuf::from(format!("/proc/{ppid}/mem"));
        out.push(("open_parent_mem", try_open(&mem, libc::O_RDONLY)));
        out.push((
            "open_etc_passwd",
            try_open(Path::new("/etc/passwd"), libc::O_RDONLY),
        ));
        out.push((
            "write_input_dir",
            try_open(&dir.join("in/probe"), libc::O_WRONLY | libc::O_CREAT),
        ));
        out.push((
            "write_parent_dir",
            try_open(&dir.join("probe"), libc::O_WRONLY | libc::O_CREAT),
        ));
        out.push((
            "read_input",
            try_open(&dir.join("in/message.eml"), libc::O_RDONLY),
        ));
        out.push((
            "write_output",
            try_open(&dir.join("out/probe"), libc::O_WRONLY | libc::O_CREAT),
        ));
        out
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    #[test]
    fn filter_fits_and_ends_in_allow() {
        let program = super::linux::filter().unwrap();
        assert!(program.len() < 4096);
        assert_eq!(program.last().unwrap().k, libc::SECCOMP_RET_ALLOW);
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
