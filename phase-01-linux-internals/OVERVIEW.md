# Phase 01 — Linux Internals & Container Security — Overview

> Running reference for recaps. Updated session by session.
> Sessions completed: 01 · 02 · 03 · 04 · 05 (in progress)

---

## The Mental Model

The kernel is the arbiter of all resources — CPU, memory, network, filesystem, processes. Nothing touches hardware directly; everything goes through the kernel via syscalls. Container security is entirely about which kernel filters are active for a given process.

```
kernel         = arbiter of all resources
namespace      = kernel filter applied per process (what it can see)
capability     = kernel permission granted per process (what it can do)
seccomp        = kernel syscall allowlist/blocklist per process
cgroup         = kernel resource quota per process group
```

Docker and Kubernetes do not create security — they configure which kernel features to activate. A misconfigured container is just a process with kernel filters disabled.

---

## Session 01 — Dockerfile Security

**Core finding:** A vulnerable Dockerfile is an exploit chain waiting for one RCE.

### Red Flags in a Dockerfile

| Pattern | Risk |
|---------|------|
| `USER root` | Container escape = immediate root on host |
| `appuser ALL=(ALL) NOPASSWD:ALL` in sudoers | `USER appuser` is meaningless — one `sudo su` away from root |
| `netcat`, `wget`, `curl` in prod image | Attacker toolkit pre-installed |
| `RUN echo 'root:password123' \| chpasswd` | Exposed in `docker history` permanently |
| `chmod -R 777 /app` | Any process can overwrite app code → backdoor on restart |
| `pip install` without `--require-hashes` | Supply chain: typosquatting, dependency confusion |
| SSH daemon in container | Persistent network attack surface; debug via `docker exec` instead |

### Exploit Chain: RCE → Full Cluster Compromise

```
RCE on app (running as root)
  → check /var/run/docker.sock  → mount host filesystem
  → check CapEff = 0xffffffff   → mount /dev/sda1 → host filesystem
  → read kubelet credentials    → kubectl as node
  → create privileged pod on every node
  → enumerate all secrets across cluster
```

### Fix Pattern

```dockerfile
FROM python:3.11-slim
RUN useradd -r -s /bin/false appuser
COPY --chown=appuser:appuser . /app
RUN pip install --require-hashes -r requirements.txt
USER appuser
EXPOSE 8080
CMD ["python", "app.py"]
```

---

## Session 02 — SUID, World-Writable Paths, sudo Misconfiguration

**Core finding:** Filesystem permissions are a privilege boundary. Misconfigurations collapse that boundary.

### Permission Concepts

| Permission | Meaning | Attack |
|------------|---------|--------|
| `777` on directory | Any user can delete any file | Evidence destruction, file replacement |
| `777` on log file | Any user can write | Log poisoning, log truncation |
| `666` on `.env` | World-readable secrets | DB passwords, API keys exposed to any local user |
| SUID bit on binary | Runs as file owner (often root) | Privilege escalation via binary exploitation |
| Sticky bit (`1777`) | World-writable but only owner can delete | Correct model for `/tmp`, shared dirs |
| `NOPASSWD:ALL` in sudoers | Passwordless root | One command from any shell: `sudo su -` |

### Fix Pattern

```bash
chmod 1777 /opt/shared          # sticky: world-writable, owner-delete only
chmod 1770 /tmp/uploads         # group-only + sticky
chown root:appgroup /tmp/uploads
touch /var/log/app.log
chown appuser:appgroup /var/log/app.log
chmod 640 /var/log/app.log      # owner rw, group r, others nothing

# Narrow sudo — only the exact command needed
echo "deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp" >> /etc/sudoers
visudo -c  # always validate before saving
```

---

## Session 03 — Docker Capabilities

**Core finding:** Capabilities are fine-grained kernel permissions. Each one you add is an attack surface you hand to any process in the container.

### The Four Dangerous Caps

| Capability | What the kernel unlocks | Exploit |
|------------|------------------------|---------|
| `SYS_ADMIN` | mount(), nsenter, unshare, kernel settings | `mount /dev/sda1 /mnt` → host FS; `insmod malicious.ko` → kernel code exec |
| `SYS_PTRACE` | `ptrace()` on any process in same PID namespace | Read memory of processes holding TLS keys, passwords, tokens |
| `NET_ADMIN` | Modify interfaces, routes, iptables, packet capture | Sniff/redirect all traffic on the node |
| `DAC_OVERRIDE` | Bypass file permission checks | Read `/etc/shadow`, any private key, regardless of ownership |

`SYS_ADMIN` + `SYS_PTRACE` + `NET_ADMIN` + `DAC_OVERRIDE` together ≈ `--privileged`.

### Fix Pattern

```bash
docker run -d \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --security-opt seccomp=./seccomp-profile.json \
  --read-only \
  --tmpfs /tmp:size=50m,noexec \
  myapp:latest
```

---

## Session 04 — Seccomp

**Core finding:** Seccomp is a syscall allowlist enforced by the kernel. `security_opt: []` removes Docker's default profile — every syscall becomes available.

### Dangerous Syscalls

| Syscall | Attack vector |
|---------|--------------|
| `ptrace` | Attach to any process, read memory (credentials, keys) |
| `fork` | Spawn shells, run binaries, fork bomb |
| `mount` | Access host block devices if available |
| `init_module` / `finit_module` | Load kernel modules → arbitrary kernel code exec |
| `kexec_load` | Replace the running kernel |
| `reboot` | Reboot the host from a container |
| `pivot_root` | Change root filesystem |
| `unshare` | Create new namespaces (namespace escape prep) |

Docker's default seccomp profile blocks ~44 syscalls. Setting `security_opt: []` disables it entirely.

### Fix Pattern

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    { "names": ["read","write","open","close","stat","mmap","exit_group"], "action": "SCMP_ACT_ALLOW" }
  ]
}
```

```yaml
# docker-compose.yml
security_opt:
  - seccomp=./seccomp-profile.json
```

---

## Session 05 — Linux Namespaces

**Core finding:** Namespaces are kernel filters. Sharing a namespace with the host = sharing that kernel resource with the host. No filter = no isolation.

### Namespace Types

| Namespace | Kernel isolates | If shared with host |
|-----------|----------------|---------------------|
| `pid` | Process tree | Container sees every process on the node |
| `net` | Network stack | Container sees all host network interfaces and traffic |
| `mnt` | Mount table | Container sees host filesystem mounts |
| `ipc` | SysV IPC, POSIX MQ | Container can access host shared memory |
| `uts` | hostname, domainname | Container can change host hostname |
| `user` | UID/GID + capabilities | root in container = UID 0 on host (no remapping) |
| `cgroup` | cgroup root | Container sees host cgroup tree |

Docker default: PID, net, mnt, ipc, uts are isolated. **`user` namespace is shared by default** — root inside is real root on the host.

### Three Namespace Operations

```bash
# Observe — what namespaces does a process live in?
sudo ls -la /proc/$PID/ns/
# Same inode = shared namespace. Different inode = isolated.

# Create — launch a process with new namespaces
sudo unshare --pid --fork --mount-proc bash   # isolated PID tree
sudo unshare --net bash                        # isolated network stack
sudo unshare --mount bash                      # isolated mount table
unshare --user --map-root-user bash            # fake root, real UID unchanged

# Enter — join namespaces of a running process
sudo nsenter -t $PID -n ip addr   # enter only net namespace
sudo nsenter -t $PID -p ps aux    # enter only PID namespace
sudo nsenter -t $PID -a sh        # enter ALL namespaces = docker exec bypass
```

`nsenter` is the IR tool when `docker exec` is unavailable — works directly via the kernel regardless of runtime state.

### Red Flag Pattern — "Monitoring Sidecar"

```yaml
monitor:
  image: ubuntu:22.04
  pid: "host"               # shares host PID namespace
  network_mode: "host"      # shares host network namespace
  cap_add:
    - SYS_PTRACE            # can read memory of any process
  volumes:
    - /proc:/host-proc:ro   # direct /proc access even without pid:host
```

This pattern appears as "observability sidecars," "log collectors," "health agents." The stated purpose does not change the kernel-level access.

### Detect Namespace Sharing

```bash
# Docker — all running containers
docker ps --quiet | while read cid; do
  echo "=== $cid ==="
  docker inspect $cid --format 'PID: {{.HostConfig.PidMode}} | Net: {{.HostConfig.NetworkMode}} | UTS: {{.HostConfig.UTSMode}}'
done

# Kubernetes — pods with host namespaces
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(.spec.hostNetwork == true or .spec.hostPID == true or .spec.hostIPC == true) |
  "\(.metadata.namespace)/\(.metadata.name): hostNetwork=\(.spec.hostNetwork) hostPID=\(.spec.hostPID) hostIPC=\(.spec.hostIPC)"
'

# Kubernetes — pods with hostPath volumes
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(.spec.volumes[]?.hostPath != null) |
  "\(.metadata.namespace)/\(.metadata.name): hostPaths=[\(.spec.volumes[] | select(.hostPath != null) | .hostPath.path)]"
'
```

### Hardened vs Broken — Quick Reference

**Docker**
```bash
# Broken
docker run --pid=host --network=host --privileged nginx

# Hardened
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE --read-only nginx
```

**Kubernetes**
```yaml
# Broken
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - securityContext:
      privileged: true

# Hardened
spec:
  containers:
  - securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]
```

### Detection Rules

**Falco** (runtime — alerts after the fact):
```yaml
- rule: Container running with hostPID
  condition: container.privileged = true or (proc.pname = dockerd and proc.cmdline contains "pid host")
  output: Container with host PID namespace (container=%container.id image=%container.image)
  priority: WARNING
```

**OPA Gatekeeper** (admission — blocks before the pod runs):
```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPHostNamespace
metadata:
  name: no-host-namespaces
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

```
Gatekeeper = prevent (admission control)
Falco      = detect (runtime, eBPF/kernel module)
```

---

## Cross-Session Attack Surface Map

```
Dockerfile vulns (S01)
  → root process in container
  → + SYS_ADMIN cap (S03)     → mount host disk → host FS access
  → + SYS_PTRACE cap (S03)    → read process memory → steal secrets
  → + seccomp disabled (S04)  → call any kernel syscall
  → + pid:host namespace (S05) → see all node processes
  → + net:host namespace (S05) → sniff all node traffic
  → full node compromise
  → steal kubelet credentials
  → full cluster compromise
```

Each session removes one layer of defense. A production hardened container needs all layers active simultaneously.

---

## Hardened Container — Baseline Config

```bash
docker run -d \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --security-opt seccomp=./seccomp-profile.json \
  --read-only \
  --tmpfs /tmp:size=50m,noexec \
  --user 1000:1000 \
  myapp:latest
```

```yaml
# Kubernetes pod spec baseline
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
containers:
- securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: ["ALL"]
      add: ["NET_BIND_SERVICE"]
```

---

---

## Session 06 — cgroups: Resource Limits & Availability Attacks

**Core finding:** Missing resource limits are not just an ops problem — they are an availability attack vector. In a shared cluster, an unbounded container can starve or kill unrelated workloads on the same node.

### What cgroups do

The kernel translates Kubernetes `resources.limits` into cgroup parameters on the node. Without limits, the cgroup has no constraint — the container can consume everything available.

```
requests → scheduler (where to place the pod)
limits   → kernel cgroup enforcement (ceiling — CPU throttle, memory OOM kill)
```

A container with no `requests` is treated as requesting zero — it lands on any node. A container with no `limits` has no kernel ceiling.

### Attack Scenarios

| Scenario | Vector | Node Impact |
|----------|--------|-------------|
| Memory leak in `api` container | No memory limit → consumes all node RAM | OOM killer evicts other pods on same node — cross-team blast radius |
| ReDoS in one replica | No CPU limit → one pod consumes all CPU | Other replicas on same node starve — degraded availability |
| RCE → fork bomb | No PID limit → exhausts kernel PID table (global resource) | No new processes anywhere on node — runtime, kubelet, system all fail |
| No `requests` → scheduler misplacement | All 3 replicas land on same node (scheduler sees 0 consumption) | Single node failure = all replicas gone simultaneously |

### Requests vs Limits

```
requests = what the scheduler reserves for placement decisions
limits   = what the kernel enforces at runtime via cgroups

No requests → scheduler can co-locate unlimited pods on one node
No limits   → kernel applies no ceiling → noisy neighbor / fork bomb / OOM cascade
```

### Hardened YAML

```yaml
containers:
- name: api
  resources:
    requests:
      memory: "256Mi"
      cpu: "250m"
    limits:
      memory: "512Mi"    # 2x request — allows burst without immediate OOM kill
      cpu: "1000m"
- name: redis
  resources:
    requests:
      memory: "128Mi"
      cpu: "100m"
    limits:
      memory: "256Mi"
      cpu: "500m"
```

### LimitRange — enforce defaults cluster-wide

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: production
spec:
  limits:
  - type: Container
    default:
      memory: "256Mi"
      cpu: "500m"
    defaultRequest:
      memory: "128Mi"
      cpu: "100m"
    max:
      memory: "2Gi"
      cpu: "2"
```

Any container in the namespace with no `resources` block gets these defaults applied automatically.

### Verify cgroup enforcement

```bash
# Docker — no limits (returns max int64 = unlimited)
docker run -d --name unlimited redis:7
cat /sys/fs/cgroup/memory/docker/<id>/memory.limit_in_bytes
# 9223372036854771712

# Docker — with limits (returns 268435456 = 256 MiB)
docker run -d --name limited --memory=256m --cpus=0.5 redis:7
cat /sys/fs/cgroup/memory/docker/<id>/memory.limit_in_bytes
# 268435456
```

### Kubernetes QoS Classes (OOM kill priority)

| QoS Class | Definition | OOM kill order |
|-----------|-----------|----------------|
| `Guaranteed` | All containers have equal requests = limits | Killed last |
| `Burstable` | At least one container has a request or limit | Middle |
| `BestEffort` | No containers have requests or limits | Killed first |

A container with no `resources` block = `BestEffort` = first victim of OOM killer. This is why limits are not optional in production.

### Detection

```bash
# Find pods with no resource limits in a namespace
kubectl get pods -n production -o json | jq -r '
  .items[] | .metadata.name as $name |
  .spec.containers[] |
  select(.resources.limits == null) |
  "\($name): \(.name) has no limits"
'
```

---

*Sessions 07–12 appended as completed.*
