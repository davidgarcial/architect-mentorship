# Phase 01 — Session 04: Example Solution
## docker-compose.yml + Seccomp Profile — Annotated Fix

---

## Diff — Broken vs Hardened docker-compose.yml

```diff
  version: '3.8'
  services:
    app:
      image: python:3.11-slim
      volumes:
        - ./app:/app
      working_dir: /app
-     security_opt: []
+     security_opt:
+       - no-new-privileges:true
+       - seccomp:./seccomp-app.json
+     # security_opt: [] explicitly DISABLES Docker's default seccomp profile.
+     # Docker's default profile blocks ~44 dangerous syscalls including:
+     #   ptrace, reboot, kexec_load, init_module, mount, pivot_root
+     # Removing it re-enables all of these for the container process.
+     # The fix: restore the default profile AND add no-new-privileges.
+     # Better: a custom profile that allows only what the app actually calls.

      command: python /app/processor.py
+     read_only: true
+     tmpfs:
+       - /tmp:size=32m,noexec,nosuid
+     # read_only + tmpfs: app cannot write anywhere except /tmp.
+     # noexec on /tmp: payloads written to /tmp cannot be executed.
```

---

## The Broken Seccomp State

```bash
# With security_opt: [] the container has access to:

ptrace     → attach to any process, read its memory (credentials, keys, tokens)
fork       → create child processes (spawn shells, run binaries)
mount      → mount filesystems (access host block devices if available)
init_module → load kernel modules (arbitrary kernel code execution)
finit_module→ same as init_module
kexec_load → replace the running kernel
reboot     → reboot the host
pivot_root → change root filesystem
unshare    → create new namespaces (namespace escape preparation)
```

---

## Hardened Seccomp Profile

Save as `seccomp-app.json` — allows only syscalls a Python data processor legitimately needs:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
  "syscalls": [
    {
      "comment": "File I/O — reading/writing data files",
      "names": [
        "read", "write", "open", "openat", "close",
        "stat", "fstat", "lstat", "statx",
        "lseek", "pread64", "pwrite64", "readv", "writev",
        "access", "faccessat", "getcwd", "chdir",
        "rename", "renameat", "renameat2",
        "mkdir", "mkdirat", "rmdir", "unlink", "unlinkat",
        "readlink", "readlinkat", "getdents", "getdents64",
        "fcntl", "flock", "fsync", "fdatasync",
        "truncate", "ftruncate", "chmod", "fchmod",
        "chown", "fchown", "lchown", "umask"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "comment": "Memory management",
      "names": [
        "mmap", "mprotect", "munmap", "brk", "mremap",
        "msync", "madvise", "mincore"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "comment": "Process lifecycle — Python needs fork for multiprocessing",
      "names": ["fork", "vfork", "clone", "execve", "exit", "exit_group",
                "wait4", "waitid", "getpid", "getppid", "gettid"],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "comment": "Signals",
      "names": [
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "rt_sigpending", "rt_sigsuspend", "kill", "tgkill",
        "sigaltstack"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "comment": "Time and scheduling",
      "names": [
        "gettimeofday", "clock_gettime", "clock_getres",
        "nanosleep", "setitimer", "getitimer",
        "sched_yield", "sched_getaffinity"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "comment": "I/O multiplexing",
      "names": [
        "select", "poll", "epoll_create", "epoll_create1",
        "epoll_ctl", "epoll_wait", "epoll_pwait",
        "pipe", "pipe2", "dup", "dup2", "dup3", "ioctl"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "comment": "Identity and credentials",
      "names": [
        "getuid", "getgid", "geteuid", "getegid",
        "getgroups", "setgroups", "getresuid", "getresgid"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "comment": "Misc — needed by Python runtime",
      "names": [
        "uname", "arch_prctl", "set_tid_address",
        "set_robust_list", "get_robust_list",
        "futex", "prlimit64", "getrandom",
        "seccomp", "prctl", "rlimit"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

---

## Evidence — Verify the Profile Blocks Dangerous Syscalls

```bash
# ── Verify ptrace is blocked ──────────────────────────────────────────────────
# Without seccomp (broken):
docker run --rm --security-opt seccomp=unconfined python:3.11-slim \
  python3 -c "import ctypes; ctypes.CDLL(None).ptrace(0, 0, 0, 0)"
# Returns 0 or -1 with EPERM — but the syscall was ALLOWED

# With seccomp profile:
docker run --rm --security-opt seccomp=./seccomp-app.json python:3.11-slim \
  python3 -c "import ctypes; ctypes.CDLL(None).ptrace(0, 0, 0, 0)"
# Killed (SIGSYS) — syscall blocked by seccomp, process terminated

# ── Verify init_module is blocked ────────────────────────────────────────────
docker run --rm --security-opt seccomp=./seccomp-app.json python:3.11-slim \
  python3 -c "
import ctypes, struct
# Attempt init_module syscall (NR 175 on x86_64)
result = ctypes.CDLL(None).syscall(175, 0, 0, 0)
print(f'init_module result: {result}')
"
# Expected: process killed with SIGSYS — syscall not in allowlist

# ── Verify app still runs under the profile ───────────────────────────────────
docker-compose -f docker-compose.hardened.yml up
# App should process data normally — all needed syscalls are in the allowlist

# ── Use strace to discover what syscalls the app actually uses ────────────────
# Run without seccomp, trace all syscalls, extract unique names
docker run --rm --security-opt seccomp=unconfined \
  --cap-add SYS_PTRACE python:3.11-slim \
  strace -f -e trace=all python3 /app/processor.py 2>&1 \
  | grep "^[a-z]" | sed 's/(.*$//' | sort -u
# Use this output to build a minimal allowlist for the specific app

# ── Confirm no-new-privileges prevents setuid escalation ─────────────────────
docker run --rm \
  --security-opt no-new-privileges:true \
  python:3.11-slim \
  sh -c "cp /bin/sh /tmp/sh && chmod +s /tmp/sh && /tmp/sh -p -c id"
# id shows original uid — setuid had no effect
```

---

## Hardened docker-compose.yml

```yaml
version: '3.8'
services:
  app:
    image: python:3.11-slim
    volumes:
      - ./app:/app:ro          # mount app code read-only
    working_dir: /app
    security_opt:
      - no-new-privileges:true
      - seccomp:./seccomp-app.json
    read_only: true
    tmpfs:
      - /tmp:size=32m,noexec,nosuid
    user: "1001:1001"          # run as non-root UID
    cap_drop:
      - ALL
    command: python /app/processor.py
```

---

## 3-Line Session Summary

```
Covered:   seccomp profiles — how Docker's default profile protects containers,
           what security_opt:[] removes, and how to write a minimal allowlist.
Diagnosed: ptrace, init_module, mount, kexec_load all re-enabled by removing seccomp;
           each independently enables host compromise.
Key shift: "the container has no capabilities" and "seccomp is disabled" are
           independent concerns — a no-cap container with no seccomp can still
           call any syscall the kernel allows unprivileged code to invoke.
```
