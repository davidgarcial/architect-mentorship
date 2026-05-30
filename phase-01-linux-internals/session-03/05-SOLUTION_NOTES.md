# Phase 01 — Session 03: Solution Notes
## Linux Capabilities

### Conceptual Answers

**What problem do capabilities solve, and why is "just use root" wrong?**
Before capabilities, privilege was binary: you were UID 0 (can do anything) or you were not (can do almost nothing). Capabilities split root's power into ~40 granular units. `CAP_NET_BIND_SERVICE` lets a process bind to ports < 1024. `CAP_CHOWN` lets it change file ownership. This matters for security because: a web server only needs `CAP_NET_BIND_SERVICE` — if it's compromised, the attacker gets that one capability, not all 40. "Just use root" means a single exploit gives the attacker everything.

**Why is CAP_SYS_ADMIN the dangerous one?**
`CAP_SYS_ADMIN` is the "god capability" — it covers mount operations, kernel module loading, namespace manipulation, device access, and dozens of other privileged operations. In practice, a container with `CAP_SYS_ADMIN` can almost always escape to the host: mount the host filesystem, create new namespaces that overlap with host namespaces, load a malicious kernel module. It's so broad that giving a container `CAP_SYS_ADMIN` is nearly equivalent to `--privileged`.

**How do ambient capabilities allow privilege without setuid?**
Ambient capabilities (Linux 4.3+) persist across `execve()` into non-privileged programs. Traditionally, capabilities were only inherited if the binary had them in its file capability set. Ambient capabilities let you run a binary *without* setuid and *without* file capabilities while still passing capabilities to child processes. An attacker who can write to an ambient capability set can grant themselves capabilities across exec calls.

### Key Commands
```bash
# List capabilities of a process
cat /proc/$$/status | grep Cap
capsh --decode=$(cat /proc/$$/status | grep CapEff | awk '{print $2}')

# List capabilities on a file
getcap /usr/bin/ping
# ping: cap_net_raw=ep

# Set a capability on a file (adds net bind without setuid)
sudo setcap cap_net_bind_service=ep /usr/local/bin/myserver

# Remove all capabilities from a file
sudo setcap -r /usr/local/bin/myserver

# Drop capabilities in Docker
docker run --cap-drop ALL --cap-add NET_BIND_SERVICE myimage

# Check what a container actually has
docker inspect <container> | grep -A20 CapAdd
```

### Exploit Chain: CAP_NET_RAW Abuse
```
Container deployed with default Docker capabilities (includes CAP_NET_RAW)
→ Attacker gets RCE inside container
→ Uses CAP_NET_RAW to perform ARP spoofing on container network
→ Intercepts traffic between other containers on the same bridge network
→ Captures authentication tokens or credentials in plaintext
→ Pivots to other services using stolen credentials
(No container escape needed — lateral movement within the cluster)
```

### Docker Default Capabilities (what every container gets)
```
CAP_AUDIT_WRITE    CAP_CHOWN        CAP_DAC_OVERRIDE
CAP_FOWNER         CAP_FSETID       CAP_KILL
CAP_MKNOD          CAP_NET_BIND_SERVICE  CAP_NET_RAW
CAP_SETFCAP        CAP_SETGID       CAP_SETPCAP
CAP_SETUID         CAP_SYS_CHROOT
```
Most production containers need none of these except possibly `CAP_NET_BIND_SERVICE`.

### Hardened Docker Run
```bash
docker run \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --no-new-privileges \
  --read-only \
  myapp
```

### Evidence It Works
- `capsh --decode=$(cat /proc/1/status | grep CapEff | awk '{print $2}')` inside container shows only `cap_net_bind_service`
- `ping 8.8.8.8` inside container fails with "permission denied" (no CAP_NET_RAW)
- App still binds to port 443 successfully
