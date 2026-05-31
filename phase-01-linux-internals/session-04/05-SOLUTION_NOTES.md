# Phase 01 — Session 04: Solution Notes
## Syscall Interface: strace and seccomp

### Conceptual Answers

**What is a system call and why is it the kernel boundary that matters for security?**
User-space code runs in ring 3 (unprivileged). To access hardware, the network, the filesystem, or other processes, it must ask the kernel via a system call. The kernel runs in ring 0. Every syscall crosses that boundary — it's the chokepoint through which all privileged operations flow. If you control which syscalls a process can make, you control what it can do. seccomp operates at this boundary: it intercepts every syscall before the kernel executes it.

**Why can't you just whitelist by syscall name? Why do you also need argument filtering?**
`openat(AT_FDCWD, "/etc/passwd", O_RDONLY)` and `openat(AT_FDCWD, "/etc/shadow", O_RDONLY)` are the same syscall number (`openat` = 257 on x86_64). Whitelisting `openat` allows both. To block reading `/etc/shadow` while allowing `/etc/passwd` you need argument-level filtering — seccomp-bpf allows you to inspect syscall arguments using Berkeley Packet Filter programs. `openat` on a path containing "shadow" can be blocked while `openat` generally is permitted.

**What is the difference between SECCOMP_MODE_STRICT and SECCOMP_MODE_FILTER?**
`SECCOMP_MODE_STRICT`: only allows `read`, `write`, `exit`, `sigreturn`. Anything else kills the process with SIGKILL. Useful only for compute-only processes with no I/O.
`SECCOMP_MODE_FILTER` (seccomp-bpf): uses a BPF program to make per-syscall decisions: ALLOW, KILL, TRAP, ERRNO. This is what Docker/Kubernetes uses. The default Docker seccomp profile blocks ~44 syscalls (including `ptrace`, `kexec_load`, `mount`, `unshare`).

### Key Commands
```bash
# Trace all syscalls of a command
strace ls 2>&1 | head -30

# Count syscalls by type
strace -c ls 2>/dev/null

# Trace a running process
strace -p <PID>

# Trace only specific syscalls
strace -e trace=openat,read,write ls

# Trace with timestamps
strace -ttt -e trace=network curl https://example.com

# Check what seccomp profile a container is using
docker inspect <container> | grep -i seccomp

# Run with no seccomp (dangerous, for testing only)
docker run --security-opt seccomp=unconfined myimage
```

### Build: Minimal Seccomp Profile
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "read", "write", "close", "fstat", "mmap", "mprotect",
        "munmap", "brk", "rt_sigaction", "rt_sigprocmask",
        "ioctl", "access", "execve", "exit", "exit_group",
        "openat", "newfstatat", "lseek", "pread64",
        "getdents64", "geteuid", "getuid", "getgid", "getegid",
        "socket", "connect", "sendto", "recvfrom", "bind",
        "listen", "accept4", "setsockopt", "getsockopt",
        "futex", "set_robust_list", "clock_gettime",
        "getpid", "getppid", "arch_prctl", "set_tid_address"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

### Exploit Chain: ptrace Abuse
```
Container lacks seccomp profile (or has seccomp=unconfined)
→ Attacker gets RCE as non-root user inside container
→ Attacker calls ptrace(PTRACE_ATTACH, <pid of root process>)
→ Reads/writes memory of root process
→ Injects shellcode into root process's memory
→ Root process executes shellcode
→ Attacker has root inside container
→ Now attempts container escape
```
With default Docker seccomp: `ptrace` is blocked → EPERM → attack fails at step 3.

### Evidence It Works
```bash
# Verify your app runs with strace and shows only expected syscalls
strace -c -e trace=all ./myapp 2>&1 | grep -v "No child"
# You should see: read, write, openat, futex, close — nothing else

# Apply custom seccomp profile
docker run --security-opt seccomp=myprofile.json myimage

# Confirm ptrace is blocked
docker run --security-opt seccomp=myprofile.json myimage \
  strace -p 1  # should fail with "ptrace: Operation not permitted"
```
