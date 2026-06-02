# Session 06 — Lab Guide

> Hands-on with cgroups, resource limits, and DOS demonstrations. Target: 90 min.

---

## Setup (5 min)

```bash
# Verify
docker --version
stress --version || sudo apt-get install -y stress stress-ng
# Optional but helpful
sudo apt-get install -y cgroup-tools
```

---

## Exercise 1 — Inspect cgroup Hierarchy (15 min)

```bash
# 1. What cgroup version is your system using?
mount | grep cgroup | head -3
# cgroup2 in output = v2; otherwise = v1

# 2. Show all cgroups
ls /sys/fs/cgroup/

# 3. Show the cgroups of your current shell
cat /proc/self/cgroup

# 4. For Docker containers
docker run -d --name target --rm alpine sleep 3600
docker top target
PID=$(docker inspect --format '{{.State.Pid}}' target)
cat /proc/$PID/cgroup
# This shows the cgroup path for THIS container — usually /docker/<container-id> or similar

# 5. Inspect what limits are set
cat /sys/fs/cgroup/system.slice/docker-${CID}.scope/cpu.max 2>/dev/null     # cgroup v2
cat /sys/fs/cgroup/cpu/docker/${CID}/cpu.cfs_quota_us 2>/dev/null            # cgroup v1
# Output 'max' or '-1' = unlimited.

# Cleanup
docker stop target
```

---

## Exercise 2 — Demonstrate Unlimited CPU = DOS (15 min)

```bash
# 1. Run a CPU-heavy container with NO limits
docker run -d --name nolimits --rm alpine sh -c "while true; do :; done & while true; do :; done & while true; do :; done & wait"

# 2. Watch host CPU
top                                      # press 'P' to sort by CPU
# Observe: container at ~300% CPU (3 cores busy)

# 3. Now constrain it with a CPU limit
docker stop nolimits
docker run -d --name limited --rm --cpus="0.5" alpine sh -c "while true; do :; done & while true; do :; done & wait"
top
# Observe: container capped at 50% of ONE core regardless of how many busy loops it runs.

docker stop limited
```

---

## Exercise 3 — Memory Limit and OOM-Kill (15 min)

```bash
# 1. Container that tries to allocate 1GB with a 256MB limit
docker run --rm -m 256m --memory-swap=256m alpine sh -c "
  stress --vm 1 --vm-bytes 1G --vm-hang 5
"
# Output: OOM-killed (you'll see exit code 137 = 128 + 9 SIGKILL)

# 2. Container with NO memory limit (vulnerable on small hosts)
# DON'T run this on a host you care about — it can hang the kernel briefly
docker run --rm alpine sh -c "stress --vm 1 --vm-bytes 4G --vm-hang 5"
# On a host with sufficient RAM, this just eats it. Other workloads start to suffer.

# 3. Check kernel OOM killer log
sudo dmesg | grep -i "Out of memory" | tail -5
```

---

## Exercise 4 — Fork Bomb DOS (15 min — BE CAREFUL)

```bash
# WARNING: only do this in a VM you can reboot. Don't do this on a production host.

# 1. Demonstrate fork bomb in container with NO pid limit
docker run --rm alpine sh -c ":(){ :|:& };:" &
# Within a few seconds, the host runs out of PIDs. Other docker commands hang.

# 2. Container with pid limit (defense)
docker run --rm --pids-limit=50 alpine sh -c ":(){ :|:& };:" &
# Fork bomb hits 50 PIDs and gets ENOMEM. Host is fine.
```

---

## Exercise 5 — Write Proper Limits for K8s (20 min)

Take the exercise artifact (Deployment YAML with no resources). Add a proper resources block.

```yaml
# Before (vulnerable)
spec:
  containers:
  - name: api
    image: myapp:latest

# After (defended)
spec:
  containers:
  - name: api
    image: myapp:latest
    resources:
      requests:
        cpu: "100m"           # 0.1 CPU guaranteed
        memory: "256Mi"
      limits:
        cpu: "500m"           # 0.5 CPU maximum
        memory: "512Mi"
        ephemeral-storage: "1Gi"
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop: ["ALL"]
```

---

## Exercise 6 — Cluster-Wide Enforcement (10 min)

```yaml
# LimitRange — applies defaults to namespace
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: production
spec:
  limits:
  - default:
      cpu: "500m"
      memory: "512Mi"
    defaultRequest:
      cpu: "100m"
      memory: "128Mi"
    type: Container

---
# ResourceQuota — caps total namespace usage
apiVersion: v1
kind: ResourceQuota
metadata:
  name: production-quota
  namespace: production
spec:
  hard:
    requests.cpu: "10"
    requests.memory: "20Gi"
    limits.cpu: "20"
    limits.memory: "40Gi"
    count/pods: "50"
```

---

## Acceptance Criteria

- [ ] Identified cgroup version (v1 or v2) on your system
- [ ] Demonstrated CPU limit prevents DOS
- [ ] Demonstrated memory limit triggers OOM-kill
- [ ] Demonstrated pids-limit prevents fork bomb
- [ ] Wrote a defended K8s Deployment with resources + securityContext
- [ ] Wrote a LimitRange + ResourceQuota for namespace-level enforcement

---

## Reading

- cgroups v2: https://www.kernel.org/doc/Documentation/cgroup-v2.txt
- K8s resource management: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
- "How to set CPU and memory in K8s" — Sysdig blog
- LimitRange / ResourceQuota: K8s docs
