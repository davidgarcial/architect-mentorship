# Phase 01 — Session 06: Solution Notes
## cgroups: Resource Limits and Security Implications

### Conceptual Answers

**What security problem do cgroups solve beyond resource fairness?**
Without cgroups, a single container can exhaust host CPU, memory, or file descriptors — denying service to every other container on the host. This is a Denial of Service attack that requires no privilege escalation and no exploit: just `while true; do :; done` or `:(){ :|:& };:` (fork bomb). cgroups enforce hard limits that the kernel enforces regardless of what the process does. A container that hits its memory limit gets OOM-killed rather than starving the host.

**Why does a container without memory limits create a noisy-neighbor DoS vector?**
All containers on a host share the kernel's memory. Without a memory limit, a compromised or misbehaving container can allocate until the host OOM killer activates — and the OOM killer may kill processes in *other* containers before killing the offender (it picks by heuristics: highest memory consumption, lowest OOM score). The compromised container can use this to selectively kill processes: allocate memory until the OOM killer targets a specific PID.

**What is the difference between a soft limit and a hard limit in cgroups?**
- **Soft limit** (`memory.soft_limit_in_bytes`): advisory limit. The kernel respects it only under memory pressure. Under normal conditions the process can exceed it.
- **Hard limit** (`memory.limit_in_bytes`): absolute maximum. The process is OOM-killed the moment it tries to exceed it.
Production containers should always have hard limits. Soft limits alone provide no DoS protection.

### Key Commands
```bash
# Check cgroup version
stat -f /sys/fs/cgroup  # if type=cgroup2fs → v2, tmpfs → v1

# View cgroup of a running container
cat /proc/$(docker inspect -f '{{.State.Pid}}' <container>)/cgroup

# View resource limits via cgroup v2
cat /sys/fs/cgroup/system.slice/docker-<id>.scope/memory.max
cat /sys/fs/cgroup/system.slice/docker-<id>.scope/cpu.max

# Run container with explicit limits
docker run \
  --memory=256m \
  --memory-swap=256m \
  --cpus=0.5 \
  --pids-limit=100 \
  --ulimit nofile=1024:1024 \
  myapp

# Verify inside container
cat /sys/fs/cgroup/memory.max   # should show 268435456 (256MB in bytes)

# Fork bomb test (with limits — safe)
docker run --pids-limit=20 ubuntu bash -c ':(){ :|:& };:'
# Container gets killed, host is fine
```

### Exploit Chain: No PID Limit
```
Container deployed without --pids-limit
→ Attacker exploits app vulnerability → RCE inside container
→ Runs fork bomb: :(){ :|:& };:
→ PID table fills up (default Linux max: 32768 PIDs)
→ Host cannot fork new processes — systemd, sshd, kubelet all fail
→ Cluster node becomes unresponsive
→ Node is evicted/replaced — attacker triggers this deliberately
→ During the chaos and re-scheduling, attacker exploits race conditions
   in new pod scheduling to get privileged placement
```

### Docker Compose with Limits
```yaml
services:
  api:
    image: myapp
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
        reservations:
          cpus: '0.25'
          memory: 128M
    ulimits:
      nofile:
        soft: 1024
        hard: 1024
    pids_limit: 100
```

### Evidence It Works
```bash
# Memory limit enforced
docker run --memory=64m ubuntu python3 -c "x = 'a' * 200_000_000"
# Killed (OOM)

# CPU limit enforced
docker run --cpus=0.1 ubuntu stress --cpu 4 &
# top on host shows container capped at ~10% CPU

# PID limit enforced
docker run --pids-limit=5 ubuntu bash -c 'for i in {1..10}; do sleep 100 & done'
# bash: fork: retry: Resource temporarily unavailable
```
