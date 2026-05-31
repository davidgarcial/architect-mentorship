# Phase 01 — Linux Deep Internals | Session 04 of 12

## Topic
Syscall interface: strace, seccomp

## Session Goal
Train the ability to read a container's syscall behavior and write a seccomp profile that eliminates the attack surface — rather than accepting Docker's default profile as "good enough."

## The Artifact
A `docker-compose.yml` that runs a Python script with seccomp explicitly disabled (`security_opt: []`). The Python script presents itself as a data processor but uses syscalls that have no legitimate place in a containerized application: `ptrace`, `fork`, and direct `/proc` reads. Your job is to identify each dangerous syscall, explain the attack vector it enables, and write a seccomp profile (as a JSON file) that blocks them while allowing the application to function.

**docker-compose.yml:**
```yaml
version: '3.8'
services:
  app:
    image: python:3.11-slim
    volumes:
      - ./app:/app
    working_dir: /app
    command: python3 suspicious.py
    security_opt: []   # explicitly empty — no seccomp
    privileged: false
```

**app/suspicious.py:**
```python
import os, ctypes, subprocess

# "Legitimate" app logic
print("Starting data processor...")

# Hidden: uses ptrace syscall via ctypes
PTRACE_TRACEME = 0
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.ptrace(PTRACE_TRACEME, 0, 0, 0)

# Attempts to read /proc/1/maps (host PID 1 if pid namespace shared)
try:
    with open('/proc/1/maps', 'r') as f:
        print(f.read()[:200])
except:
    pass

# Fork bomb potential
os.fork()
```

Note: `security_opt: []` overrides Docker's default seccomp profile with nothing. The default Docker seccomp profile blocks ~44 syscalls. Setting this to an empty list means the container runs with the kernel's full syscall table available.

## Background (read after attempting the artifact)
- **The syscall interface:** Every interaction between a userspace process and the kernel goes through a syscall. There are ~350 syscalls on x86_64 Linux. Programs use them for everything: reading files (`read`, `open`), creating processes (`fork`, `clone`, `execve`), managing memory (`mmap`, `mprotect`), and kernel-level operations (`ptrace`, `mount`, `kexec_load`). A container without seccomp has access to all of them.
- **seccomp (Secure Computing Mode):** A kernel feature that installs a BPF filter on a process's syscall table. When the process attempts a syscall, the filter runs and can allow it, block it (returning `EPERM`), or kill the process. Docker applies a default seccomp profile that blocks ~44 syscalls including `ptrace`, `kexec_load`, `mount`, `reboot`, and others. `security_opt: []` disables this entirely.
- **ptrace and why it matters:** `ptrace` is the syscall behind `strace`, `gdb`, and every debugger. It allows a process to attach to another process, read and write its memory, and intercept its syscalls. In a container sharing the host PID namespace, an attacker with `ptrace` access can read secrets from any process on the host. Even within a private PID namespace, an attacker can use `ptrace` to inject code into another container process or dump its memory.
- **fork and resource exhaustion:** `os.fork()` with no rate limit is the foundation of a fork bomb. Each `fork()` duplicates the calling process. A loop that calls `fork()` repeatedly creates 2^n processes, exhausting the kernel's PID table and system memory. Without a cgroup PID limit, a single container can take down a node. The `suspicious.py` script only forks once, but the syscall being unrestricted means nothing prevents a more aggressive version.
- **strace as an auditing tool:** `strace` records every syscall a process makes, with arguments and return values. Running `strace -f -e trace=all python3 suspicious.py` gives a complete picture of what the application actually does vs what it claims to do. This is one of the first tools to reach for when auditing a container image.

## Exercise

### Step 1 — Run the container and observe its syscalls from outside
Create the directory structure (`mkdir -p app`), save `suspicious.py` to `./app/suspicious.py`, and bring up the compose stack. Then from the host, use strace to observe its syscalls:
```bash
docker-compose up -d
# Get the container PID on the host
docker inspect <container_id> --format '{{.State.Pid}}'
# Attach strace to the running process
sudo strace -p <host_pid> -f -e trace=all 2>&1 | head -50
```
Alternatively, run it directly with strace inside a container:
```bash
docker run --rm -it \
  --security-opt seccomp=unconfined \
  -v $(pwd)/app:/app \
  python:3.11-slim \
  strace -f -e trace=all python3 /app/suspicious.py 2>&1
```
Identify the `ptrace` and `clone`/`fork` syscalls in the output.

### Step 2 — Identify what each dangerous syscall enables
For each of the following syscalls that appear in the script's execution, write a one-paragraph explanation of what the syscall does and what an attacker could do with unrestricted access to it in a container context: `ptrace`, `clone` (used by `fork`), `open`/`openat` on `/proc` paths.

Then check: what does Docker's default seccomp profile already block? Compare against your list:
```bash
# Download Docker's default seccomp profile
curl -s https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json \
  | python3 -m json.tool | grep '"name"' | sort
```

### Step 3 — Write a custom seccomp profile
Create `seccomp-profile.json` that allows the syscalls a legitimate Python data processor needs (file I/O, memory management, basic process control) and explicitly blocks `ptrace`, `fork`/`clone` with CLONE_NEWPID, and restricts `/proc` access patterns.

A minimal seccomp profile structure:
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "open", "openat", "close", "fstat", "mmap", "exit_group"],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["ptrace"],
      "action": "SCMP_ACT_ERRNO"
    }
  ]
}
```

Apply it:
```bash
docker run --rm \
  --security-opt seccomp=./seccomp-profile.json \
  -v $(pwd)/app:/app \
  python:3.11-slim \
  python3 /app/suspicious.py
```
Confirm the `ptrace` call fails with `EPERM` and the fork is blocked (or limited). Tune the allowlist until the "legitimate" print statement works but the dangerous syscalls are blocked.

## Your Deliverable
Write your findings in `SOLUTION.md` in this folder. For each finding use:
```
## Finding N: [name]
**Line(s)/Location:** ...
**What it is:** ...
**Exploit chain:** attacker does X → which enables Y → end state is Z
**Impact:** ...
**Fix:** ...
```

## Acceptance Criteria

### FUNCTIONAL
- [ ] `docker-compose up` runs the container successfully
- [ ] strace output captured and included in SOLUTION.md showing actual syscalls

### SECURITY
- [ ] `ptrace` syscall identified in strace output and exploit chain documented
- [ ] `fork`/`clone` identified and fork bomb scenario written out
- [ ] `security_opt: []` vs default seccomp documented with specific syscalls that are now unblocked
- [ ] Each finding includes full exploit chain, not just a label

### OBSERVABLE
- [ ] Custom `seccomp-profile.json` included in session folder
- [ ] Evidence that applying the profile blocks `ptrace` (error message or strace showing EPERM)
- [ ] strace output snippet included showing the dangerous syscalls

### STRETCH
- [ ] Use `strace` to generate an exhaustive list of every syscall `python3 suspicious.py` makes, then write a tight allowlist profile that permits only those syscalls — test that the app works and that `ptrace` is blocked
- [ ] Investigate what `SCMP_ACT_LOG` does and configure it as the default action (instead of ERRNO) to audit blocked syscalls without breaking the app

## Offline Notes
- `strace -f` follows child processes (forks). `-e trace=process` limits to process-related syscalls. `-e trace=file` limits to file operations.
- `strace -c` gives a summary count of syscall frequency — useful for profiling what a program actually uses
- Docker's default seccomp profile JSON: https://github.com/moby/moby/blob/master/profiles/seccomp/default.json
- seccomp-bpf documentation: https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
- `ausyscall --dump` lists all syscall names and numbers for the current architecture
- `libseccomp` tools: `scmp_sys_resolver ptrace` resolves syscall name to number
- `/proc/self/status` field `Seccomp`: 0 = no filter, 1 = strict mode, 2 = filter mode
- Key syscalls to always block in containers: `ptrace`, `kexec_load`, `kexec_file_load`, `mount`, `umount2`, `reboot`, `swapon`, `swapoff`, `syslog`, `process_vm_readv`, `process_vm_writev`, `pivot_root`, `chroot`, `unshare`, `clone` with CLONE_NEWUSER flag
- `man 2 ptrace`, `man 2 seccomp`, `man 2 clone`

## Session Summary Template
```
Session 04 complete.
Covered: [fill in]
Key insight: [fill in]
Gap identified: [fill in]
```
