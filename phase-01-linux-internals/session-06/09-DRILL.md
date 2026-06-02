# Session 06 — Daily Drill

> 15 min. cgroup inspection and resource-limit commands until automatic.

---

## The Six Commands

```bash
# 1. What cgroup version is this system?
mount | grep cgroup | head -3

# 2. List all cgroups
ls /sys/fs/cgroup/

# 3. What cgroup is my shell in?
cat /proc/self/cgroup

# 4. What cgroup is a specific PID in?
cat /proc/<PID>/cgroup

# 5. Read CPU limit for a container (cgroup v2)
cat /sys/fs/cgroup/<path>/cpu.max
# Output: "max 100000" = no limit; "50000 100000" = 50% of 1 CPU

# 6. Read memory limit for a container (cgroup v2)
cat /sys/fs/cgroup/<path>/memory.max
# Output: "max" = no limit; bytes otherwise
```

---

## Drill Routine — 15 min daily, 7 days

**Day 1-2:** Run each command with reference. Understand the output.
**Day 3-5:** Run from memory.
**Day 6-7:** Add bonus commands; achieve fluency.

---

## Reading cgroup v2 Output

cgroup v2 is the modern unified hierarchy. Key files in each cgroup directory:

| File | What it controls |
|---|---|
| `cpu.max` | CPU quota: `<quota> <period>` (e.g., `50000 100000` = 50%) |
| `cpu.weight` | CPU weight when contending (1-10000, default 100) |
| `memory.max` | Hard memory limit (OOM-kill at this) |
| `memory.high` | Soft limit (throttle before OOM) |
| `memory.low` | Protected memory (won't reclaim below this) |
| `pids.max` | Max PIDs in this cgroup (fork-bomb defense) |
| `io.max` | IO bandwidth per device |
| `cgroup.procs` | List of PIDs in this cgroup |

---

## Bonus Commands (Week 2)

```bash
# 7. List ALL containers and their CPU + memory limits
for cid in $(docker ps -q); do
  name=$(docker inspect $cid --format '{{.Name}}')
  cpu=$(docker inspect $cid --format '{{.HostConfig.NanoCpus}}')
  mem=$(docker inspect $cid --format '{{.HostConfig.Memory}}')
  echo "$name | cpu=$cpu mem=$mem"
done

# 8. Identify K8s pods with NO resource limits
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(.spec.containers[] | (.resources.limits // null) == null) |
  "\(.metadata.namespace)/\(.metadata.name)"
'

# 9. Identify K8s pods with no requests (they get over-scheduled)
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(.spec.containers[] | (.resources.requests // null) == null) |
  "\(.metadata.namespace)/\(.metadata.name)"
'

# 10. Read live cgroup stats (v2)
cat /sys/fs/cgroup/<path>/cpu.stat
# Output: usage_usec, user_usec, system_usec, nr_periods, nr_throttled, throttled_usec
# nr_throttled > 0 means the cgroup is being CPU-limited.

# 11. Read memory pressure events
cat /sys/fs/cgroup/<path>/memory.pressure
# Lines like: "some avg10=0.00 avg60=0.00 avg300=0.00 total=0"
# total > 0 means memory pressure has been experienced

# 12. Real-time cgroup monitoring
systemd-cgtop
```

---

## Quick Reference — Common Misconfigurations

| Setting | Symptom | Fix |
|---|---|---|
| No `limits.cpu` | One pod uses entire node CPU | Set explicit `limits.cpu` |
| No `limits.memory` | OOM on host kernel, not pod | Set explicit `limits.memory` |
| No `pids` limit | Fork bomb takes down node | Set `pids` limit or `pids.max` cgroup |
| `requests` >> `limits` | Burstable QoS — pod evicted under pressure | Make them closer (Guaranteed QoS) |
| `requests` == 0 | Pod over-scheduled | Set realistic requests |
| Limits >> requests | Bursty workload starves co-tenants | Use NodeAffinity to isolate |

---

## Self-Check

After 1 week:
- [ ] All 6 commands from memory in 60 sec
- [ ] Can read cgroup v2 file output and interpret it
- [ ] Can identify K8s pods missing resource limits in one command
- [ ] Understand QoS classes (Guaranteed / Burstable / BestEffort)
- [ ] Know the fork-bomb defense in K8s (`pids` limit)

---

## Why this matters

Cgroups are where SLA enforcement meets security. A pod that can starve co-tenants is a security boundary violation, not just a misconfiguration. Architects who treat resource limits as "ops's problem" miss this; architects who own them prevent multi-tenant compromises before they happen.
