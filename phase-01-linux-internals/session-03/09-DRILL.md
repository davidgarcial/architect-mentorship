# Session 03 — Daily Drill

> 15 minutes. Capabilities inspection commands until they're automatic.

---

## The Five Commands You Must Memorize

```bash
# 1. What capabilities does the CURRENT process have?
capsh --print

# 2. Raw capability bitmask (when capsh isn't installed)
cat /proc/self/status | grep ^Cap

# 3. Decode a hex capability bitmask
capsh --decode=0000003fffffffff

# 4. What capabilities does a binary have set (file capabilities)?
getcap /usr/bin/ping
getcap -r / 2>/dev/null              # find ALL binaries with capabilities

# 5. Inspect another process's capabilities
cat /proc/<PID>/status | grep ^Cap
# Then decode each line:
capsh --decode=<hex-from-CapEff>
```

---

## Drill Routine — 15 minutes daily for 7 days

**Day 1-2:** Type each command, look up syntax as needed. Goal: understand what each output line means.
**Day 3-4:** Run from memory in a new shell. Time yourself.
**Day 5-7:** Add the bonus commands; aim for full fluency.

---

## Capability Bitmasks Explained

When you run `cat /proc/self/status | grep ^Cap`, you see:

```
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
```

Each line means:

| Line | What it is | Why it matters |
|---|---|---|
| `CapInh` | **Inheritable** — passes to child processes during exec | Almost always 0 outside special use cases |
| `CapPrm` | **Permitted** — capabilities the process MAY use | Maximum the process can hold |
| `CapEff` | **Effective** — capabilities currently ACTIVE | What the kernel actually checks against |
| `CapBnd` | **Bounding** — ceiling on what the process can ever gain | Caps the process can never hold, even via setuid |
| `CapAmb` | **Ambient** — caps inherited across execve of non-SUID binaries | New in Linux 4.3+; rarely used |

A non-root process with `CapEff: 0000000000000000` has zero capabilities. A "normal" privileged container has `CapEff: 00000000a80425fb` (= ~14 caps including SETUID, SETGID, NET_BIND_SERVICE).

`--privileged` containers get `CapEff: 000001ffffffffff` — ALL capabilities. That's effectively root on the host kernel.

---

## Bonus Commands (Week 2)

```bash
# Run a process with a specific capability set
capsh --caps="cap_net_raw+eip cap_setuid+eip" -- /bin/bash

# Drop all caps before executing
capsh --drop=all -- /bin/bash

# Run a container with no caps
docker run --cap-drop=ALL --rm -it alpine sh

# See ALL capabilities of all your containers at once
for c in $(docker ps -q); do
  echo "=== $c ==="
  docker inspect $c --format '{{.HostConfig.CapAdd}} added; {{.HostConfig.CapDrop}} dropped'
done

# Kubernetes: find pods with capabilities added
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(.spec.containers[].securityContext.capabilities.add != null) |
  "\(.metadata.namespace)/\(.metadata.name): \(.spec.containers[].securityContext.capabilities.add)"
'

# Check if any pod has SYS_ADMIN
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(.spec.containers[].securityContext.capabilities.add != null) |
  select(.spec.containers[].securityContext.capabilities.add | contains(["SYS_ADMIN"])) |
  "DANGER: \(.metadata.namespace)/\(.metadata.name)"
'
```

---

## Capability Quick-Reference (Top 10 to Recognize)

| Capability | What it grants | Why attackers want it |
|---|---|---|
| `CAP_SYS_ADMIN` | Mount filesystems, ptrace anyone, namespaces | Container escape via cgroup release_agent, /proc tricks |
| `CAP_SYS_PTRACE` | Trace any process, read its memory | Read secrets from other processes |
| `CAP_NET_ADMIN` | Configure network, manage routes/firewall | Sniff traffic, MITM, configure routes |
| `CAP_NET_RAW` | Raw sockets (ping, packet crafting) | Network sniffing, custom packet injection |
| `CAP_DAC_OVERRIDE` | Bypass file permission checks | Read/write any file regardless of permissions |
| `CAP_DAC_READ_SEARCH` | Bypass read/traverse checks | Read any file, traverse any directory |
| `CAP_SETUID` | Change UID to any user | Become root if not already |
| `CAP_SYS_MODULE` | Load kernel modules | Direct kernel compromise — rootkit installation |
| `CAP_CHOWN` | Change file ownership | Take ownership of anything |
| `CAP_SYS_BOOT` | Reboot system | Denial of service |

---

## Self-Check

After 1 week:

- [ ] Decode a CapEff bitmask without `capsh --decode`
- [ ] Name 5 capabilities and what they grant (without looking up)
- [ ] Spot a `--privileged` container in a docker ps output (look for the All-1s bitmask)
- [ ] List which Kubernetes pods in a cluster have non-default capabilities

---

## Why this matters

In Phase 09 (Cloud-Native Security) you'll review Kubernetes RBAC and Pod Security Standards. Without capability fluency, "block CAP_SYS_ADMIN" is a phrase you parrot. With fluency, you can audit a fleet of pods in 30 seconds and identify which ones are equivalent to host-root.
