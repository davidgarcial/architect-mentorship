# Phase 01 — Linux Deep Internals | Session 05 of 12

## Topic
Namespaces: PID, mount, network, user

## Session Goal
Understand what namespaces actually isolate — and what they do not — so you can immediately spot compose and pod configurations that collapse the isolation boundary between containers and the host.

## The Artifact
A `docker-compose.yml` with two services. The `app` service is a normal containerized Node.js application with proper network and volume isolation. The `monitor` service is presented as a "sidecar monitoring agent" but has three flags that each independently destroy namespace isolation: `pid: "host"`, `network_mode: "host"`, and a `/proc` volume mount. Together, they create a container from which an attacker can observe and interact with every process and network connection on the node.

```yaml
version: '3.8'
services:
  app:
    image: node:18-alpine
    networks:
      - internal
    volumes:
      - app-data:/data
    command: node server.js

  monitor:
    image: ubuntu:22.04
    pid: "host"
    network_mode: "host"
    cap_add:
      - SYS_PTRACE
    volumes:
      - /proc:/host-proc:ro
    command: sleep infinity

networks:
  internal:

volumes:
  app-data:
```

This pattern appears in real environments as "observability sidecars," "log collectors," and "health check agents." The security implication is the same regardless of the stated purpose.

## Background (read after attempting the artifact)
- **What Linux namespaces are:** A namespace wraps a global system resource in an abstraction so that processes inside the namespace see their own isolated instance of the resource. Docker creates new namespaces for each container by default — a new PID namespace (so the container thinks it has its own PID 1), a new network namespace (its own interfaces and routing table), a new mount namespace (its own filesystem tree), and optionally a user namespace. Bypassing any of these with `host` mode collapses the isolation for that resource type.
- **`pid: "host"` — what it exposes:** When a container shares the host PID namespace, it can see every process running on the node — including processes from other containers, the container runtime itself (dockerd, containerd), the kubelet (in Kubernetes), and all host system processes. The process list from inside this container is the same as running `ps aux` on the host. Combined with `SYS_PTRACE`, this means the monitor container can attach to any process on the node with `ptrace()`, read its memory, and extract secrets (environment variables, in-memory credentials, TLS private keys).
- **`network_mode: "host"` — what it exposes:** The container gets no network namespace of its own. It shares the host's network stack directly. This means it can bind to any port on the host (including ports used by other services), it can see all network traffic visible to the host's interfaces, it can set the interface to promiscuous mode and capture all packets, and it bypasses all Docker network policies and inter-container network isolation. In Kubernetes, this also bypasses NetworkPolicy enforcement since the pod is on the host network, not the pod network.
- **`/proc:/host-proc:ro` — what it exposes:** Even in read-only mode, mounting the host's `/proc` inside a container gives access to `/proc/1/environ` (environment variables of PID 1, which often contains secrets), `/proc/net/tcp` and `/proc/net/tcp6` (all open TCP connections on the host with hex-encoded addresses), memory maps of all processes, open file descriptors, and the full process tree. The `:ro` flag prevents writing to the mounted proc filesystem but does not prevent reading it. An attacker reads `/proc/<pid>/environ` for every process and harvests all secrets in seconds.
- **Namespace isolation in Kubernetes:** Kubernetes adds its own layers — NetworkPolicy controls east-west traffic between pods, Pod Security Standards restrict host namespace usage at the pod level. But none of this matters if a pod spec explicitly sets `hostPID: true`, `hostNetwork: true`, or `hostIPC: true`. These are the pod-level equivalents of the compose flags above. A security architect needs to catch these in admission control (OPA/Gatekeeper or Kyverno policies) before they reach a cluster.

## Exercise

### Step 1 — Bring up the stack and inventory what the monitor container can see
```bash
docker-compose up -d
docker exec -it <monitor_container> bash

# Inside the monitor container:
# List all processes on the node (not just in the container)
ps aux

# List all network interfaces on the host
ip addr show

# List all open network connections on the host
ss -tulnp

# Read the host's /proc/1/environ (init/systemd environment)
cat /host-proc/1/environ | tr '\0' '\n'

# List all processes from /proc directly
ls /host-proc/ | grep -E '^[0-9]+$' | wc -l
```
Document the difference between what you see inside the `app` container (exec into it for comparison) and what you see inside the `monitor` container.

### Step 2 — Trace the lateral movement path
From inside the monitor container, demonstrate the path to reaching the `app` container's data:
```bash
# Find the app container's process ID (visible because pid: host)
ps aux | grep node

# Read the app process's environment variables
cat /host-proc/<app_pid>/environ | tr '\0' '\n'

# Read the app process's open file descriptors
ls -la /host-proc/<app_pid>/fd

# With SYS_PTRACE (already added), you could attach:
# strace -p <app_pid>  — intercepts all syscalls of the target process
```
Write out the full lateral movement chain: attacker compromises the monitor container → uses pid:host to enumerate all processes → finds app container PID → reads /proc/<pid>/environ for database credentials → uses credentials from outside the container network.

### Step 3 — Identify the correct configuration for a legitimate monitoring sidecar
A legitimate monitoring agent (like Prometheus node-exporter or Datadog) needs to collect metrics from the host. What is the minimum set of access it actually needs? Rewrite the `monitor` service in the compose file to have only what is required for metric collection — no `pid: host`, no `network_mode: host`, no raw `/proc` mount. Consider using specific `/proc` subdirectory mounts (e.g., `/proc/meminfo:/host-proc/meminfo:ro`) instead of the full `/proc` tree.

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
- [ ] `docker-compose up` brings both services up
- [ ] Commands in Step 1 run successfully from inside the monitor container

### SECURITY
- [ ] Exploit chain for `pid: "host"` documented with actual `ps aux` output showing host processes
- [ ] Exploit chain for `network_mode: "host"` documented with `ss -tulnp` output
- [ ] `/proc` mount exploitation documented (env vars read from another process)
- [ ] Each finding includes full exploit chain, not just a label

### OBSERVABLE
- [ ] Output of `cat /host-proc/1/environ` (or equivalent) included in SOLUTION.md
- [ ] Process count comparison between app container and monitor container included
- [ ] Hardened compose config included in SOLUTION.md

### STRETCH
- [ ] Write a Kyverno or OPA/Gatekeeper policy that would reject any pod spec with `hostPID: true`, `hostNetwork: true`, or `hostIPC: true`
- [ ] Test whether the `app` container (with proper isolation) can see the monitor container's processes — explain why or why not based on how PID namespaces work

## Offline Notes
- `lsns` — lists all namespaces on the system with their types and the process holding them open
- `nsenter --target <pid> --pid --net --mount bash` — enters the namespaces of an existing process. This is how Docker exec works internally.
- `/proc/<pid>/ns/` — directory containing symlinks to each namespace the process belongs to. The inode numbers tell you which namespaces are shared.
- User namespaces (`--userns-remap` in Docker) add an additional layer: mapping container UID 0 to an unprivileged host UID. This is disabled by default in most Docker installations.
- In Kubernetes, the Pod Security Standards `restricted` profile prohibits `hostPID`, `hostIPC`, and `hostNetwork`. The `baseline` profile also prohibits them. Only the `privileged` profile allows them — and that should never be the default.
- `man 7 namespaces`, `man 2 unshare`, `man 1 nsenter`
- Key `/proc` paths for reconnaissance: `/proc/net/tcp` (open TCP sockets), `/proc/net/arp` (ARP table, reveals adjacent hosts), `/proc/<pid>/cmdline` (process command line), `/proc/<pid>/maps` (memory layout, reveals loaded libraries)

## Session Summary Template
```
Session 05 complete.
Covered: [fill in]
Key insight: [fill in]
Gap identified: [fill in]
```
