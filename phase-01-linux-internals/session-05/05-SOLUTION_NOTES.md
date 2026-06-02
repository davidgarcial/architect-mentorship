# Phase 01 — Session 05: Solution Notes
## Namespaces: PID, Mount, Network, User

### Conceptual Answers

**What does a namespace actually isolate, and what does it NOT isolate?**
A namespace gives a process a private view of one specific kernel resource:
- **PID namespace**: process sees its own PID tree. PID 1 inside the namespace is not the host's PID 1.
- **Mount namespace**: private filesystem view. Mounts don't propagate to other namespaces.
- **Network namespace**: private network interfaces, routing table, iptables. Container's `eth0` is a veth pair connected to a bridge on the host.
- **User namespace**: maps UIDs inside the namespace to UIDs outside. UID 0 inside can map to UID 1001 outside.

What namespaces do NOT isolate: kernel resources (syscalls go to the same kernel), time (`/proc/uptime` reflects host uptime), the kernel itself (a kernel exploit breaks all containers). Namespaces are isolation, not security in depth — they're one layer, not the whole story.

**Why does the user namespace allow non-root users to create containers?**
Normally creating namespaces requires `CAP_SYS_ADMIN`. User namespaces are special: an unprivileged user can create a new user namespace and, within it, get a full capability set mapped to their unprivileged host UID. Rootless Docker uses this: Docker daemon runs as your user, containers run in a user namespace where UID 0 maps to your host UID. If the container escapes, it gets your host UID — not host root.

**How does a shared PID namespace between containers create a security risk?**
If two containers share a PID namespace (`--pid=container:other`), they can see each other's processes and send signals to them. More critically: `/proc/<pid>/mem` is readable (with `ptrace`) — one container can read another's memory. If container A is a secrets manager and container B is a compromised app in the same PID namespace, container B can read container A's memory and extract secrets.

### Key Commands
```bash
# List namespaces of a process
ls -la /proc/$$/ns/

# Create a new network namespace manually
sudo ip netns add myns
sudo ip netns exec myns ip addr show
# Only loopback — fully isolated network

# Check what namespaces a container uses
docker inspect <container> | grep -i pid
ls -la /proc/$(docker inspect -f '{{.State.Pid}}' <container>)/ns/

# Create a minimal container using unshare (no Docker)
sudo unshare --pid --mount --fork --mount-proc /bin/bash
# Now inside: PID namespace — ps shows only our shell and ps itself

# Check if two containers share a namespace
ls -la /proc/<pid1>/ns/net /proc/<pid2>/ns/net
# Same inode = same namespace

# Rootless Docker check
docker info | grep -i rootless
cat /proc/$(pgrep dockerd)/status | grep Uid
```

### Exploit Chain: Shared PID Namespace
```
Microservices app: secrets-manager container + api container
Dev deploys both with --pid=container:secrets-manager (for debugging)
→ Attacker exploits SQL injection in api container → RCE
→ Runs: ls /proc/ — sees PIDs from secrets-manager container
→ Finds PID of secrets-manager process (PID 7)
→ Reads /proc/7/environ → all environment variables including API_SECRET_KEY
→ Uses key to authenticate directly to external services
(No exploit of secrets-manager needed — shared namespace did the work)
```

### Verify Namespace Isolation
```bash
# Good: containers in separate PID namespaces
# Inside container A:
ls /proc/ | wc -l  # only a handful of PIDs — just container A's processes

# Bad: containers sharing PID namespace
# Inside container A:
ls /proc/ | wc -l  # hundreds of PIDs — you can see host and container B

# Verify network isolation
# Inside container A:
ip addr show  # only eth0 (veth) and lo — not host's interfaces

# Verify mount isolation
# Inside container A:
mount | grep "^/dev"  # only container-specific mounts, not host disks
```

### Common Mistakes
- Thinking namespaces = security. They are isolation, not hardening. A kernel exploit breaks through all namespaces simultaneously.
- Using `--pid=host` for debugging in production. This gives the container full visibility into all host processes.
- Not checking that a volume mount (`-v /host/path:/container/path`) doesn't break mount namespace isolation for the mounted path.
