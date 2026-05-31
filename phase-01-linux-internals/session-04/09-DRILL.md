# Session 04 — Daily Drill

> 15 min. strace + seccomp inspection commands until they're automatic.

---

## The Five Commands

```bash
# 1. Trace a command and summarize
strace -c <command>

# 2. Trace only specific syscall categories
strace -e trace=network <command>          # network: socket, connect, send, recv, etc.
strace -e trace=file <command>             # file: open, read, write, stat, etc.
strace -e trace=process <command>          # process: fork, exec, wait, exit

# 3. Attach to a running process
sudo strace -p <PID>

# 4. Read a container's seccomp status (host side)
docker inspect <container-id> | grep -i seccomp
grep Seccomp /proc/<container-pid>/status   # 0=disabled, 1=strict, 2=filter

# 5. Show Docker's default seccomp profile syscall list
curl -sL https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json | jq '.syscalls[].names[]' | sort -u | head
```

---

## Drill Routine — 15 minutes daily, 7 days

**Day 1-2:** Run each from scratch on your WSL. Look up flags as needed.
**Day 3-4:** Type from memory. Time yourself — aim for under 90 seconds for all 5.
**Day 5-7:** Add the bonus commands; achieve fluency.

---

## Reading strace output — what each column means

```
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 45.23    0.000023           1        17           openat
 22.11    0.000011           1         8           read
 ...
```

- **% time** — share of total wall time spent in this syscall
- **seconds** — total time spent in this syscall
- **usecs/call** — average microseconds per call
- **calls** — number of times the syscall was made
- **errors** — number of times it returned an error
- **syscall** — the syscall name

**Key insight:** if `% time` is dominated by a single syscall (>50%), that's where the process spends its life. Optimize there.

---

## Bonus Commands (Week 2)

```bash
# 6. Trace AND follow child processes (important for shell scripts)
strace -f -e trace=process bash -c 'ls | grep test'

# 7. Get only failed syscalls
strace -e trace=all -Z <command> 2>&1 | grep -E '= -1|^[a-z].*=.*-1'

# 8. Trace with timestamps (for matching with logs)
strace -t -e trace=network <command>

# 9. Trace and write to file (less noise on screen)
strace -o /tmp/trace.log <command>

# 10. List all syscalls allowed by the current seccomp policy
# (Requires being inside a container or process with policy)
cat /proc/self/status | grep Seccomp_filters
# Number of installed filters — 0 means none

# 11. Decode a denied syscall by name from dmesg
dmesg | grep -i seccomp | tail
# Format: "audit: type=1326 audit(...): ... syscall=N"
# Map syscall number with: ausyscall <N>
```

---

## Quick Cheat Sheet — Common Syscalls to Recognize

| Syscall | What it does | Why attackers care |
|---|---|---|
| `execve` | Execute a binary | Shell spawning, code execution |
| `clone`, `fork` | Spawn a process | Fork bombs, post-exploitation lateral processes |
| `unshare` | Detach into new namespace | Container escape prerequisite (CVE-2022-0185) |
| `mount` | Mount filesystem | Container escape via cgroups |
| `ptrace` | Trace another process | Read memory, inject code (credential theft) |
| `socket` + `connect` | Network connection | C2 callback, data exfiltration |
| `openat` (with `/etc/shadow`, `/root/.ssh/`) | Sensitive file access | Credential theft |
| `bpf` | Load eBPF program | Network sniffing, kernel-level hooks |
| `init_module` | Load kernel module | Rootkit installation |
| `setuid` (called from a SUID binary) | Change UID | Privilege escalation |

---

## Self-Check

After 1 week:
- [ ] All 5 commands from memory in under 90 seconds
- [ ] Can read strace summary output and identify dominant syscalls
- [ ] Recognize 10 syscalls from the cheat sheet without lookup
- [ ] Can write a 5-line seccomp profile from a strace output

---

## Why this matters

When you architect a workload, you decide its syscall surface. A workload that only needs `read/write/socket/connect` has 99% of the kernel attack surface eliminated by a seccomp profile. Most engineers never think about this — most engineers also can't prevent the next kernel CVE from affecting them. Architects can.
