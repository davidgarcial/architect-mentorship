# Session 05 — Lab Guide

> Hands-on with Linux namespaces. Target: 90 minutes.

---

## Setup (5 min)

```bash
# Verify tools (usually pre-installed)
unshare --help | head -2
nsenter --help | head -2
docker --version
```

---

## Exercise 1 — Inspect Namespaces (15 min)

```bash
# 1. List your own process's namespaces
ls -la /proc/self/ns/
# Each is a symlink to a namespace ID — same ID = same namespace.

# 2. Compare to a container
docker run -d --rm --name target alpine sleep 3600
PID=$(docker inspect --format '{{.State.Pid}}' target)
ls -la /proc/$PID/ns/
# Different IDs = different namespaces. Same IDs = shared with host.

# 3. List namespaces system-wide
lsns
# Shows every namespace and how many processes are in it.

# 4. Per-type listing
lsns -t pid          # PID namespaces only
lsns -t net          # Network namespaces only
lsns -t user         # User namespaces only

# Cleanup
docker stop target
```

---

## Exercise 2 — Create Namespaces with unshare (20 min)

```bash
# 1. New PID namespace (this fails as non-root without --user)
sudo unshare --pid --fork --mount-proc bash
# Inside: ps aux shows ONLY bash itself and ps
exit

# 2. New network namespace — fully isolated
sudo unshare --net bash
# Inside: ip a shows only loopback
exit

# 3. New mount namespace — changes don't affect host
sudo unshare --mount bash
# Inside: mount -o remount,ro / does NOT remount the host root
# But /proc/mounts changes inside the namespace
exit

# 4. User namespace — non-root creates a "root" inside
unshare --user --map-root-user bash
# Inside: id shows uid=0
# But from host: ps -o uid,pid,cmd shows your real UID
exit
```

the kernel isolates resources by type. Each namespace wraps exactly one resource. A process lives in one namespace of each type simultaneously.

Namespace	Isolates	Observable via
pid	Process tree	ps aux shows only local PIDs
net	Network stack	ip a shows only loopback
mnt	Mount table	private copy of /proc/mounts
user	UID/GID + capabilities	id shows uid=0, host sees real UID
ipc	SysV IPC, POSIX MQ	shared memory segments
uts	hostname, domainname	hostname is independent
cgroup	cgroup root	process sees its own cgroup tree
Three operations:

/proc/$PID/ns/ — read which namespaces a process is in (same inode = shared namespace)
unshare — create new namespaces for a new process
nsenter — enter existing namespaces of a running process
Security implication: shared namespace = shared attack surface. If user namespace is shared (Docker default), root in the container is UID 0 on the host. If pid namespace is shared (--pid=host), the container sees every process on the node.

**Drill question:** what does the kernel actually enforce for an "unshared" user namespace's root? (Hint: capabilities only apply within the namespace.)

---

## Exercise 3 — Enter Existing Container Namespaces with nsenter (20 min)

```bash
# 1. Start a container
docker run -d --rm --name target alpine sh -c "sleep 3600"
PID=$(docker inspect --format '{{.State.Pid}}' target)

# 2. Enter its network namespace from the host
sudo nsenter -t $PID -n ip addr
# You see the container's network interfaces from your host shell.

# 3. Enter its mount namespace
sudo nsenter -t $PID -m mount | head -5
# Container's view of mounts, from host.

# 4. Enter its PID namespace
sudo nsenter -t $PID -p ps aux
# Container's process list (just sh + sleep).

# 5. Enter ALL namespaces (= docker exec, but lower-level)
sudo nsenter -t $PID -a sh
# You're now "inside" the container, but via host kernel directly.

# Cleanup
docker stop target
```

**Why this matters:** `nsenter` is the IR tool when `docker exec` doesn't work (e.g., compromised container with no shell). It works from outside the runtime.

---

## Exercise 4 — Detect Namespace Sharing in Production (30 min)

The exercise artifact this session has a "monitor" service with `pid: "host"`, `network_mode: "host"`, and `/proc` mounted. Recognize this pattern.

```bash
# 1. For Docker — find containers sharing namespaces with the host
docker ps --quiet | while read cid; do
  echo "=== $cid ==="
  docker inspect $cid --format 'PID: {{.HostConfig.PidMode}} | Net: {{.HostConfig.NetworkMode}} | UTS: {{.HostConfig.UTSMode}}'
done

# 2. For Kubernetes — find pods with hostNetwork, hostPID, or hostIPC
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(
    .spec.hostNetwork == true or
    .spec.hostPID == true or
    .spec.hostIPC == true
  ) |
  "\(.metadata.namespace)/\(.metadata.name): hostNetwork=\(.spec.hostNetwork) hostPID=\(.spec.hostPID) hostIPC=\(.spec.hostIPC)"
'

# 3. Find pods with hostPath volumes (filesystem namespace breakage)
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(.spec.volumes[]?.hostPath != null) |
  "\(.metadata.namespace)/\(.metadata.name): hostPaths=[\(.spec.volumes[] | select(.hostPath != null) | .hostPath.path)]"
'
```

---

## Exercise 5 — Write a Detection Rule (15 min)

**Falco — detect when a container shares host PID namespace:**

```yaml
- rule: Container running with hostPID
  desc: Detects containers that share the host PID namespace
  condition: >
    container.privileged = true
    or (proc.pname = dockerd and proc.cmdline contains "pid host")
  output: >
    Container with host PID namespace detected
    (container=%container.id image=%container.image cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, namespace, pid]
```

**OPA Gatekeeper — block hostPID at admission:**

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

---

## Acceptance Criteria

- [ ] Identified all 5 namespace types (PID, mount, net, IPC, user, UTS, cgroup) of a running container
- [ ] Created an isolated bash with unshare in 3 different namespace types
- [ ] Used nsenter to enter container namespaces from host
- [ ] Found at least 1 container/pod with namespace sharing in your environment (or confirmed there's none)
- [ ] Detection rule written

---

## Reading

- `man 7 namespaces`
- `man 7 user_namespaces`
- Kubernetes Pod Security Standards: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- "Demystifying Containers" — Sascha Grunert's namespace series
