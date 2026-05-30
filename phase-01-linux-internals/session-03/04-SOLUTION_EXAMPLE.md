# Phase 01 — Session 03: Example Solution
## Docker Run Command — Annotated Fix

---

## The Broken Run Command

```bash
docker run -d \
  --cap-add SYS_ADMIN \
  --cap-add SYS_PTRACE \
  --cap-add NET_ADMIN \
  --cap-add DAC_OVERRIDE \
  -p 3000:3000 \
  --name nodeapp \
  nodeapp:latest
```

---

## Diff — Broken vs Hardened

```diff
  docker run -d \
- --cap-add SYS_ADMIN \
+ # REMOVED: SYS_ADMIN
+ # SYS_ADMIN covers: mount filesystems, load kernel modules, manipulate namespaces,
+ # access /proc/sys, create device nodes. A container with SYS_ADMIN can: 
+ #   mount /dev/sda1 /mnt → host filesystem
+ #   insmod malicious.ko  → arbitrary kernel code execution
+ # No application should ever need SYS_ADMIN. If it thinks it does,
+ # that operation belongs in an init container or a privileged operator pod.

- --cap-add SYS_PTRACE \
+ # REMOVED: SYS_PTRACE
+ # ptrace attaches to any process in the same PID namespace and reads its memory.
+ # In a container sharing the host PID namespace, this means reading memory of
+ # every process on the node — including processes holding TLS private keys,
+ # plaintext passwords, and authentication tokens.

- --cap-add NET_ADMIN \
+ # REMOVED: NET_ADMIN
+ # NET_ADMIN allows: modifying routing tables, adding/removing network interfaces,
+ # changing firewall rules (iptables), enabling promiscuous mode on interfaces.
+ # Promiscuous mode = read all network traffic on the node's NIC.
+ # This is a full network wiretap from inside the container.

- --cap-add DAC_OVERRIDE \
+ # REMOVED: DAC_OVERRIDE
+ # DAC_OVERRIDE bypasses all file permission checks.
+ # The attacker inside the container can read /etc/shadow, any private key,
+ # any configuration file — regardless of file permissions.
+ # Combined with a host path mount, this reads everything on the host filesystem.

+ --cap-drop ALL \
+ # Drop ALL capabilities first, then add back only what is genuinely needed.
+ # This is the correct default. A Node.js HTTP server needs zero Linux capabilities.

+ --security-opt no-new-privileges \
+ # Prevents the process inside the container from gaining new capabilities
+ # through setuid binaries or file capabilities during execution.

+ --read-only \
+ # Mount the container filesystem read-only.
+ # The application cannot write anywhere except explicitly mounted volumes.
+ # Makes persistence and backdoor installation impossible from inside the container.

+ --tmpfs /tmp:size=50m,noexec \
+ # /tmp is needed by many apps. Mount it as tmpfs with:
+ #   size=50m: limits /tmp to 50MB (prevents resource exhaustion)
+ #   noexec: binaries written to /tmp cannot be executed
+ # This breaks the common attacker pattern: download payload to /tmp, chmod +x, run.

  -p 3000:3000 \
  --name nodeapp \
  nodeapp:latest
```

---

## Hardened Run Command

```bash
docker run -d \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --security-opt seccomp=./seccomp-node.json \
  --read-only \
  --tmpfs /tmp:size=50m,noexec \
  --tmpfs /var/tmp:size=10m,noexec \
  -p 3000:3000 \
  --name nodeapp \
  nodeapp:latest
```

---

## Companion: Minimal seccomp Profile for Node.js

Save as `seccomp-node.json`:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "close", "stat", "fstat", "lstat",
        "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "ioctl", "pread64", "pwrite64", "readv", "writev",
        "access", "pipe", "select", "sched_yield", "mremap",
        "msync", "mincore", "madvise", "shmget", "shmat", "shmctl",
        "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm",
        "setitimer", "getpid", "sendfile", "socket", "connect",
        "accept", "sendto", "recvfrom", "sendmsg", "recvmsg",
        "shutdown", "bind", "listen", "getsockname", "getpeername",
        "socketpair", "setsockopt", "getsockopt", "clone", "fork",
        "vfork", "execve", "exit", "wait4", "kill", "uname",
        "fcntl", "flock", "fsync", "fdatasync", "truncate",
        "ftruncate", "getdents", "getcwd", "chdir", "rename",
        "mkdir", "rmdir", "unlink", "readlink", "chmod", "fchmod",
        "chown", "fchown", "lchown", "umask", "gettimeofday",
        "getrlimit", "getrusage", "sysinfo", "times", "getuid",
        "getgid", "geteuid", "getegid", "setgroups", "getgroups",
        "gettid", "futex", "sched_getaffinity", "set_tid_address",
        "clock_gettime", "clock_getres", "epoll_create", "epoll_wait",
        "epoll_ctl", "tgkill", "openat", "getdents64", "set_robust_list",
        "get_robust_list", "accept4", "epoll_create1", "dup3",
        "pipe2", "prlimit64", "getrandom", "statx"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

---

## Evidence — Verify Each Control

```bash
# Build image
docker build -t nodeapp:latest .

# ── Capability verification ───────────────────────────────────────────────────
# Broken: all four caps present
docker run --rm \
  --cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add NET_ADMIN --cap-add DAC_OVERRIDE \
  nodeapp:latest cat /proc/self/status | grep CapEff
# CapEff: high value — all 4 caps encoded in the bitmask

# Hardened: no capabilities
docker run --rm \
  --cap-drop ALL --security-opt no-new-privileges \
  nodeapp:latest cat /proc/self/status | grep CapEff
# CapEff: 0000000000000000  ← zero capabilities

# ── SYS_ADMIN: can attacker mount the host filesystem? ───────────────────────
# Broken container:
docker run --rm --cap-add SYS_ADMIN nodeapp:latest \
  sh -c "mkdir /mnt/host && mount /dev/sda1 /mnt/host && ls /mnt/host"
# May succeed depending on host config — gives host filesystem access

# Hardened container:
docker run --rm --cap-drop ALL nodeapp:latest \
  sh -c "mkdir /mnt/host && mount /dev/sda1 /mnt/host"
# mount: permission denied (no CAP_SYS_ADMIN)

# ── DAC_OVERRIDE: can attacker read protected files? ─────────────────────────
# Broken container (with a bind-mounted /etc for demo):
docker run --rm --cap-add DAC_OVERRIDE -v /etc:/host-etc:ro nodeapp:latest \
  cat /host-etc/shadow
# Reads /etc/shadow regardless of permissions

# Hardened container:
docker run --rm --cap-drop ALL -v /etc:/host-etc:ro nodeapp:latest \
  cat /host-etc/shadow
# cat: /host-etc/shadow: Permission denied

# ── read-only filesystem: can attacker write a backdoor? ─────────────────────
# Hardened container:
docker run --rm --read-only nodeapp:latest \
  sh -c "echo backdoor > /app/server.js"
# /app/server.js: Read-only file system

docker run --rm --read-only --tmpfs /tmp:noexec nodeapp:latest \
  sh -c "echo '#!/bin/sh\nid' > /tmp/payload && chmod +x /tmp/payload && /tmp/payload"
# /tmp/payload: Permission denied  (noexec prevents execution)

# ── Application still works ───────────────────────────────────────────────────
docker run -d \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp:size=50m,noexec \
  -p 3000:3000 \
  --name nodeapp-test \
  nodeapp:latest

curl http://localhost:3000/health
# {"status":"ok"}  ← app functions normally with zero capabilities
docker rm -f nodeapp-test
```

---

## Capability Reference Card

```
CAP_NET_BIND_SERVICE  bind ports < 1024        low risk — common legitimate need
CAP_CHOWN             change file ownership     medium — can acquire any file
CAP_DAC_OVERRIDE      bypass file permissions   HIGH — reads any file on system
CAP_FOWNER            bypass ownership checks   HIGH — combined with DAC_OVERRIDE: full FS
CAP_SETUID / SETGID   change UID/GID            HIGH — become any user including root
CAP_SYS_PTRACE        attach debugger to proc   HIGH — read any process memory
CAP_NET_ADMIN         modify routing/interfaces HIGH — promiscuous mode = full wiretap
CAP_SYS_ADMIN         everything else           CRITICAL — effectively root on the host
```

---

## 3-Line Session Summary

```
Covered:   Four capabilities (SYS_ADMIN, SYS_PTRACE, NET_ADMIN, DAC_OVERRIDE) and what
           each one independently enables — filesystem mount, memory read, network tap,
           permission bypass.
Diagnosed: --cap-drop ALL as the correct default; capabilities added back only
           when a specific, named, justified need exists.
Key shift: "it runs as non-root" is not a security guarantee if the container
           holds capabilities — capabilities are what the kernel actually checks.
```
