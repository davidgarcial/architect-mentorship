# Session 05 — Daily Drill

> 15 min. Namespace inspection commands until automatic.

---

## The Six Commands

```bash
# 1. List my own process namespaces
ls -la /proc/self/ns/

# 2. System-wide namespace listing
lsns

# 3. Find which namespace a process belongs to
ls -la /proc/<PID>/ns/

# 4. Per-type lookup (e.g., what processes are in the same net namespace?)
lsns -t net
lsns -t pid
lsns -t user

# 5. Enter a process's namespace from outside (the IR tool)
sudo nsenter -t <PID> -a sh                # all namespaces
sudo nsenter -t <PID> -n ip addr           # net namespace only

# 6. Create new namespace inline
unshare --net --pid --fork --mount-proc bash
```

---

## Drill Routine — 15 min daily, 7 days

**Day 1-2:** Run each command with man page reference.
**Day 3-5:** Memorize. Type from scratch.
**Day 6-7:** Add bonus commands; achieve sub-90-sec fluency.

---

## Reading `/proc/<PID>/ns/` Output

```bash
ls -la /proc/self/ns/
# Output like:
# cgroup -> 'cgroup:[4026531835]'
# ipc -> 'ipc:[4026531839]'
# mnt -> 'mnt:[4026531840]'
# net -> 'net:[4026531992]'
# pid -> 'pid:[4026531836]'
# pid_for_children -> 'pid:[4026531836]'
# time -> 'time:[4026531834]'
# time_for_children -> 'time:[4026531834]'
# user -> 'user:[4026531837]'
# uts -> 'uts:[4026531838]'
```

**The number in brackets is the namespace ID.** Two processes share a namespace if their numbers match. If your container's `pid:[...]` matches the host's `pid:[...]`, the container has `hostPID: true`.

This is how you DETECT namespace sharing on a running system. Tools just wrap this.

---

## Bonus Commands (Week 2)

```bash
# 7. Compare namespace IDs between two processes
diff <(ls -la /proc/PID1/ns/ | awk '{print $11}') \
     <(ls -la /proc/PID2/ns/ | awk '{print $11}')

# 8. Show what namespaces a Docker container shares
docker inspect <container> | jq '.[0].HostConfig | {PidMode, NetworkMode, IpcMode, UTSMode, UsernsMode}'

# 9. Force a container into the host's PID namespace (the wrong way; for understanding)
docker run --rm --pid=host alpine ps auxef | head
# Shows ALL host processes — this is what attackers want

# 10. Inspect K8s pod namespace sharing
kubectl get pod <name> -o jsonpath='hostNetwork={.spec.hostNetwork} hostPID={.spec.hostPID} hostIPC={.spec.hostIPC}{"\n"}'

# 11. nsenter using PID + cgroup + IPC selectively (advanced IR)
sudo nsenter -t <PID> -p -u -i bash    # PID + UTS + IPC, NOT mount/net
```

---

## Quick Reference — Namespace Types

| Namespace | What it isolates | Sharing it means |
|---|---|---|
| `pid` | Process IDs visible | Container sees host processes |
| `net` | Network interfaces, routes, ports | Container shares host network stack |
| `mnt` | Mount points / filesystem view | Container can affect host mounts |
| `ipc` | SysV IPC, POSIX message queues | Container can communicate via shared IPC |
| `uts` | Hostname, domainname | Hostname changes affect host |
| `user` | UID/GID mappings | Without user namespace, container UID == host UID |
| `cgroup` | cgroup root | Container can see/modify cgroups outside its own |
| `time` | Boot time, monotonic clock | Time changes propagate |

**Rule:** every shared namespace is a security decision. If you didn't make it deliberately, it's a vulnerability.

---

## Self-Check

After 1 week:
- [ ] All 6 commands from memory in 60 sec
- [ ] Can identify each namespace type from `ls /proc/self/ns/`
- [ ] Can `nsenter` into a container's net namespace from memory
- [ ] Recognize hostPID/hostNetwork in K8s YAML at a glance

---

## Why this matters

In Phase 09 (Cloud-Native Security) and Phase 17 (Windows & AD) you'll review pod security and container hardening. Architects who don't have namespace inspection in their fingers are forced to trust the tool's report. Architects who do can verify it independently and spot misconfigurations the tool missed.
