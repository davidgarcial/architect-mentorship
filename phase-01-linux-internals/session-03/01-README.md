# Phase 01 — Linux Deep Internals | Session 03 of 12

## Topic
Linux capabilities: what they replace, how they get abused

## Session Goal
Move from thinking "this container is not root" to thinking "what specific kernel privileges does this container hold, and what can an attacker do with each one" — because capabilities are where container security actually lives.

## The Artifact
A Dockerfile for a Node.js application that is structured correctly on its own — it uses a non-root user and installs only what it needs. The danger is entirely in how it is run. The `docker run` command adds four capabilities that each independently enable serious attacks, and the combination enables near-total host compromise.

**Dockerfile:**
```dockerfile
FROM node:18-alpine
RUN apk add --no-cache libcap
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
USER node
CMD ["node", "server.js"]
```

**docker run command used in production:**
```bash
docker run -d \
  --cap-add=SYS_ADMIN \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_PTRACE \
  --cap-add=DAC_OVERRIDE \
  myapp:latest
```

Your task: for each capability, explain precisely what kernel operations it unlocks, build a concrete exploit chain showing how an attacker with code execution inside this container would use it, and identify which combinations are particularly dangerous together.

## Background (read after attempting the artifact)
- **The capability model:** Before capabilities, privilege was binary — you were root (UID 0) or you were not. Capabilities split root's privileges into ~40 discrete units. A process can hold capabilities without being UID 0. Docker containers run with a default set (see `man 7 capabilities`) that is already reduced from full root — but `--cap-add` adds capabilities back on top of that default set.
- **SYS_ADMIN — the "god capability":** This single capability covers mounting filesystems, loading kernel modules (`insmod`), setting hostname, accessing device files, `pivot_root`, and dozens of other operations. In practice, `SYS_ADMIN` inside a container is nearly equivalent to `--privileged`. An attacker with `SYS_ADMIN` can mount the host filesystem (`mount /dev/sda1 /mnt`), load a malicious kernel module, or use `unshare` to escape namespace isolation.
- **NET_ADMIN:** Controls all network configuration — creating/destroying interfaces, configuring iptables/nftables, setting routing tables, enabling promiscuous mode on interfaces. Inside a container with `NET_ADMIN` and `network_mode: host`, an attacker can sniff all traffic on the host, manipulate routing to redirect connections, or insert firewall rules that affect all containers on the node.
- **SYS_PTRACE:** Allows a process to use `ptrace()` to attach to any process, read/write its memory, and intercept its syscalls — regardless of the target process's owner. Inside a container sharing the host PID namespace, this enables reading secrets from any running process's memory, injecting shellcode into another process, or dumping credentials from in-memory credential stores.
- **DAC_OVERRIDE:** "Discretionary Access Control Override" — bypasses the read/write/execute permission checks on files. A process with `DAC_OVERRIDE` can read any file on the filesystem regardless of its permissions, including `/etc/shadow`, SSH private keys, and application secrets. Combined with a volume mount or a path traversal vulnerability, this collapses the entire permission model.

## Exercise

### Step 1 — Inspect what capabilities the container actually has
Build the image (you can create a minimal `server.js` that just starts an HTTP server) and run it with the provided `docker run` command. Then inspect its capability set:
```bash
# From outside the container
docker inspect <container_id> | grep -A 20 "CapAdd"

# From inside the container (exec in)
docker exec -it <container_id> sh
cat /proc/1/status | grep Cap
# The CapEff line shows the effective capability bitmask in hex
# Decode it:
capsh --decode=<hex_value>
```
Note the difference between the capability bitmask of this container vs a default `docker run ubuntu:22.04` container.

### Step 2 — Build the exploit chain for each capability
For each capability, write the specific sequence of commands an attacker would run after gaining code execution inside this container. Be concrete — include actual commands, not descriptions.

For `SYS_ADMIN`, consider: can you mount something? Can you list block devices (`lsblk`)? What happens when you try `mount -t proc proc /tmp/proc`?

For `NET_ADMIN`, consider: what does `ip link set eth0 promisc on` do, and why is that dangerous? What does `iptables -L` reveal about the host network?

For `SYS_PTRACE`, consider: if you can see host processes (Session 05 covers this further), what does `cat /proc/<pid>/mem` combined with `ptrace()` enable?

For `DAC_OVERRIDE`, consider: create a file as root with mode `600` (`chmod 600 /tmp/secret && echo "top secret" > /tmp/secret`). Then try to read it as the `node` user. Normally this fails. With `DAC_OVERRIDE`, does it?

### Step 3 — Identify the minimum required capabilities
Look up what `node server.js` actually needs to do its job (bind to a port above 1024, read files in `/app`, write logs). Which of the four added capabilities does it genuinely need? What is the correct `--cap-drop` / `--cap-add` combination for a least-privilege Node.js container?

Hint: binding to ports below 1024 requires `NET_BIND_SERVICE`. Ports above 1024 require no capability at all. A Node.js app on port 3000 needs zero capabilities beyond the Docker default set, and you should verify that by dropping all four and confirming the app still works.

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
- [ ] Container builds and runs with the provided `docker run` command
- [ ] `capsh --decode` output is included showing the full capability set

### SECURITY
- [ ] Exploit chain written for each of the four capabilities with specific commands
- [ ] Capability bitmask comparison between this container and a default Docker container is included
- [ ] Minimum required capability set identified and tested (app works with all four dropped)
- [ ] Each finding includes full exploit chain, not just a label

### OBSERVABLE
- [ ] `cat /proc/1/status | grep CapEff` output included from inside the container
- [ ] At least one capability abuse demonstrated with actual command output (not just described)
- [ ] `docker inspect` output showing `CapAdd` is included

### STRETCH
- [ ] Write a shell script that takes a container ID and outputs a human-readable capability audit: current caps, which are dangerous, and what the minimum set should be for the running process
- [ ] Find a CVE where `SYS_PTRACE` or `SYS_ADMIN` was the enabling condition for a container escape and summarize the mechanism

## Offline Notes
- `man 7 capabilities` — the definitive reference. Read the description for each cap listed in the artifact.
- `capsh --decode=<hex>` — decodes the bitmask from `/proc/$PID/status`. Install with `apt install libcap2-bin` or `apk add libcap`.
- `getpcaps <pid>` — shows capabilities of a running process in human-readable form
- Docker default capability set (as of Docker 23): `CHOWN, DAC_OVERRIDE, FSETID, FOWNER, MKNOD, NET_RAW, SETGID, SETUID, SETFCAP, SETPCAP, NET_BIND_SERVICE, SYS_CHROOT, KILL, AUDIT_WRITE`. Note: `SYS_ADMIN` is NOT in the default set.
- `--cap-drop=ALL --cap-add=NET_BIND_SERVICE` is the correct pattern for a minimal web server binding to port 80
- `/proc/self/status` fields: CapInh (inheritable), CapPrm (permitted), CapEff (effective), CapBnd (bounding set), CapAmb (ambient)
- Kernel docs: https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html

## Session Summary Template
```
Session 03 complete.
Covered: [fill in]
Key insight: [fill in]
Gap identified: [fill in]
```
