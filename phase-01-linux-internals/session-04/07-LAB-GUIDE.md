# Session 04 — Lab Guide

> Hands-on with strace, seccomp profiles, and runtime syscall observation. Target: 90 min.

---

## Setup (5 min)

```bash
# Verify tools
strace --version
docker --version

# Install if missing on Ubuntu/WSL:
sudo apt-get install -y strace
```

---

## Exercise 1 — Read a Process with strace (15 min)

```bash
# 1. Trace a simple command — what syscalls does `ls` make?
strace -c ls /tmp 2>&1 | tail -25
# The summary shows syscall counts and time per syscall.

# 2. Trace what `curl` does
strace -e trace=network curl -s https://example.com -o /dev/null 2>&1 | head -20
# Filter to just network-related syscalls.

# 3. Attach to a running process (find a long-running PID first)
ps aux | head -5
sudo strace -p <PID> -e trace=read,write 2>&1 | head -50
# Watch real-time syscalls. Ctrl+C to detach.

# 4. Time spent per syscall
strace -c -p <PID> &
sleep 5
kill %1
# Summary of what that process spent time on.
```

**Drill question:** when does a process call `openat()` vs `open()`? (Modern glibc almost always uses `openat()`.)

---

## Exercise 2 — Default Docker Seccomp vs Unconfined (20 min)

```bash
# 1. Start a normal container — default seccomp profile applied
docker run --rm -it ubuntu:22.04 bash -c "apt-get install -y libcap2-bin -qq && capsh --print 2>&1 | head -5"

# 2. Try a blocked syscall — `ptrace` requires special handling
docker run --rm -it ubuntu:22.04 bash -c "apt-get install -y strace -qq && strace -e trace=ptrace echo hi"
# In default profile: works? Test it.

# 3. Try with --security-opt seccomp=unconfined
docker run --rm -it --security-opt seccomp=unconfined ubuntu:22.04 bash -c "apt-get install -y strace -qq && strace -e trace=ptrace echo hi"
# Now ptrace works freely. That's the difference.

# 4. List syscalls blocked by default profile
curl -sL https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json | jq '.syscalls[] | select(.action != "SCMP_ACT_ALLOW") | .names[]' | head -20
```

---

## Exercise 3 — Write a Custom Seccomp Profile (30 min)

Take the artifact from this session's exercise (Python script that calls `ptrace`, `fork`, reads `/proc`). Write a seccomp profile that allows it to function but blocks the dangerous syscalls.

```bash
# 1. Start a baseline container with no seccomp — observe what the app calls
docker run --rm -d --name target --security-opt seccomp=unconfined <your-app-image>

# 2. Identify the process
docker top target

# 3. Profile it with strace
sudo strace -p <PID> -ff -c -o /tmp/syscalls 2>&1
# Wait 30 seconds, then kill strace.
# /tmp/syscalls.* contains per-thread summaries.

# 4. Get the unique syscalls used
sort -u /tmp/syscalls.* | grep -E '^[a-z]' | awk '{print $1}' | sort -u > /tmp/needed-syscalls.txt

# 5. Build a seccomp profile that allows ONLY those syscalls
cat > /tmp/profile.json <<EOF
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
  "syscalls": [
    {
      "names": [
$(cat /tmp/needed-syscalls.txt | sed 's/^/        "/' | sed 's/$/"/' | paste -sd ',')
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
EOF

# 6. Run with the custom profile
docker run --rm --security-opt seccomp=/tmp/profile.json <your-app-image>
```

**Test:** does the app still work? If it crashes immediately, you missed a required syscall — check `dmesg` for SECCOMP denials, add the syscall, retry.

---

## Exercise 4 — Detect Anomalous Syscalls with Falco (20 min)

```bash
# Run Falco
docker run -d --rm --name falco --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /dev:/host/dev \
  -v /proc:/host/proc:ro \
  falcosecurity/falco-no-driver:latest

# Trigger something Falco watches for
docker run --rm -it ubuntu:22.04 bash -c "cat /etc/shadow > /tmp/stolen.txt"
# Falco rule "Read sensitive file untrusted" fires.

# Watch the output
docker logs -f falco | grep WARNING
```

**Custom Falco rule for this session — detect unusual syscall:**
```yaml
- rule: Container calls ptrace
  desc: Detects ptrace syscall from a container, which is unusual outside debugging
  condition: >
    syscall.type = ptrace
    and container
    and not proc.name in (strace, gdb, ltrace)
  output: >
    Container called ptrace
    (container=%container.id user=%user.name proc=%proc.name)
  priority: WARNING
  tags: [container, syscall, ptrace]
```

---

## Acceptance Criteria

- [ ] strace used in 3 different modes (-c, -e trace=, -p)
- [ ] Default vs unconfined seccomp difference demonstrated
- [ ] Custom seccomp profile built for the session's exercise app
- [ ] App runs successfully under the custom profile
- [ ] Falco rule triggered at least once

---

## Reading

- `man 2 seccomp`
- Docker seccomp documentation: https://docs.docker.com/engine/security/seccomp/
- Aqua "Demystifying seccomp profiles": https://blog.aquasec.com
- Brendan Gregg on syscall tracing: https://www.brendangregg.com/blog/
