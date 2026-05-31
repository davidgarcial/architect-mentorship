# Phase 01 — Linux Deep Internals | Session 04 of 12 — Exercise Artifact

> Work with this artifact directly. Full instructions and background are in 01-README.md.

---

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
