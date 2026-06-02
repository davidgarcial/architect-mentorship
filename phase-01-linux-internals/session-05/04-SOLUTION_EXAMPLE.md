# Phase 01 — Session 05: Example Solution
## docker-compose.yml (Namespace Isolation) — Annotated Fix

---

## Diff — Broken vs Hardened

```diff
  version: '3.8'
  services:
    app:
      image: node:18-alpine
      networks:
        - internal
      volumes:
        - app-data:/data
      # App service is fine as-is

    monitor:
      image: ubuntu:22.04
-     pid: "host"
+     # REMOVED: pid: "host"
+     # pid: "host" collapses the PID namespace — the container sees and can
+     # signal every process on the node, not just its own.
+     # From inside: kill -9 <any PID on host>, ptrace <any process>,
+     # read /proc/<host-pid>/environ (environment variables of every process),
+     # read /proc/<host-pid>/mem (memory of every process — credentials, tokens, keys).
+     # A legitimate monitoring agent uses the metrics API or a dedicated socket.
+     # It never needs the host PID namespace.

-     network_mode: "host"
+     networks:
+       - internal
+     # REMOVED: network_mode: "host"
+     # network_mode: "host" collapses the network namespace — the container
+     # shares the node's network stack entirely:
+     #   - Can bind to any port on the host (including ports other services use)
+     #   - Can sniff all traffic on host interfaces (tcpdump -i eth0)
+     #   - Can modify iptables rules that affect the host and other containers
+     #   - Bypasses all Docker and CNI network policies
+     # A monitoring agent that needs network metrics should use:
+     #   - Host metrics via cAdvisor or Prometheus node exporter (purpose-built)
+     #   - Or: read /proc/net/* stats (doesn't require host network namespace)

      volumes:
-       - /proc:/host-proc:ro
-       - /sys:/host-sys:ro
+       # REMOVED: /proc and /sys host mounts
+       # Mounting the host /proc inside a container gives the container
+       # a window into the host kernel's view of every process, network
+       # connection, open file descriptor, memory map, and hardware device.
+       # Even read-only, this is a full reconnaissance capability:
+       #   /host-proc/<pid>/environ → environment variables of any process
+       #   /host-proc/<pid>/cmdline → full command line of any process
+       #   /host-proc/<pid>/fd/     → open file descriptors (including sockets)
+       #   /host-proc/net/tcp       → all TCP connections on the node
+       #   /host-sys/class/net/     → all network interfaces
+       # Legitimate monitoring: use the metrics server API (kubelet /metrics,
+       # cAdvisor), not raw /proc mounts.
+       - monitor-data:/var/lib/monitor

      command: /bin/bash -c "while true; do sleep 60; done"
+     # If this is a real monitoring agent, replace with the agent binary.
+     # bash sleep loop is not a monitoring agent — it is an idle attacker container.

+     security_opt:
+       - no-new-privileges:true
+     cap_drop:
+       - ALL

  networks:
    internal:
      driver: bridge
+     internal: true     # no external internet access from this network

  volumes:
    app-data:
+   monitor-data:
```

---

## Hardened docker-compose.yml

```yaml
version: '3.8'
services:
  app:
    image: node:18-alpine
    networks:
      - internal
    volumes:
      - app-data:/data:ro
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:size=32m,noexec,nosuid

  monitor:
    image: prom/node-exporter:latest   # purpose-built, no shell, no bash
    networks:
      - internal
    volumes:
      # node-exporter reads specific /proc paths it knows it needs
      # — not a blanket /proc mount
      - /proc/meminfo:/host/proc/meminfo:ro
      - /proc/stat:/host/proc/stat:ro
      - /sys/class/net:/host/sys/class/net:ro
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    command:
      - '--path.rootfs=/host'
      - '--web.listen-address=:9100'
    ports:
      - "127.0.0.1:9100:9100"   # only reachable from localhost

networks:
  internal:
    driver: bridge
    internal: true

volumes:
  app-data:
```

---

## Evidence — What Each Isolation Breach Enables

```bash
# ── PID namespace: host processes visible from broken container ───────────────
docker-compose -f docker-compose.broken.yml up -d

docker exec monitor ps aux
# Shows: ALL processes on the host node (kubelet, containerd, sshd, etc.)
# In hardened container: only processes inside the container are visible

# ── /proc mount: read environment of host processes ──────────────────────────
docker exec monitor bash -c "cat /host-proc/1/environ | tr '\0' '\n'"
# Prints: all environment variables of PID 1 (init/systemd on host)
# May contain: KUBECONFIG paths, AWS credentials, API keys, database URLs

# Read environment of every process to harvest credentials
docker exec monitor bash -c "
for pid in \$(ls /host-proc/ | grep '^[0-9]'); do
    env_file=\"/host-proc/\$pid/environ\"
    if [ -r \"\$env_file\" ]; then
        content=\$(tr '\0' '\n' < \"\$env_file\" 2>/dev/null)
        if echo \"\$content\" | grep -qi 'password\|secret\|key\|token'; then
            echo \"=== PID \$pid ===\"
            echo \"\$content\" | grep -i 'password\|secret\|key\|token'
        fi
    fi
done
"
# Harvests credentials from every process on the node

# ── Network namespace: sniff all traffic from broken container ────────────────
docker exec monitor tcpdump -i eth0 -w /tmp/capture.pcap &
sleep 5
docker exec monitor kill %1
docker exec monitor wc -c /tmp/capture.pcap
# Contains: all network traffic passing through the host NIC

# ── Verify hardened container cannot see host processes ──────────────────────
docker-compose -f docker-compose.hardened.yml up -d
docker exec monitor ps aux 2>/dev/null || echo "ps not available in node-exporter"
# node-exporter has no shell — attacker cannot get an interactive session at all

# ── Verify /proc mount is scoped, not blanket ─────────────────────────────────
docker exec monitor ls /host/proc/ 2>/dev/null
# Only specific files mounted — not full /proc tree
docker exec monitor cat /host/proc/meminfo
# Works: this specific file was explicitly mounted
docker exec monitor ls /host/proc/1/environ 2>/dev/null
# Fails: /proc/1/environ was NOT mounted — host process env is not accessible
```

---

## What Each Namespace Isolation Buys You

```
Namespace        | Broken (host)              | Hardened (isolated)
─────────────────┼────────────────────────────┼─────────────────────────────────
PID              | See/signal all host procs  | See only container's own procs
Network          | Read all host traffic      | Only container's virtual NIC
Mount            | (not broken here but note) | Only explicit volume mounts
/proc            | Full host kernel view      | Only explicitly mounted files
/sys             | All hardware devices       | Read-only, scoped paths only
```

---

## 3-Line Session Summary

```
Covered:   Three namespace collapse vectors — pid:host, network_mode:host,
           /proc and /sys mounts — and what each one exposes to an attacker.
Diagnosed: host PID namespace → read credentials from every process memory;
           host network namespace → full node wiretap via tcpdump;
           /proc mount → harvest environment variables of every process on node.
Key shift: isolation is not binary. Each of pid:, network_mode:, and volume
           mounts is an independent boundary — breaking one does not require
           breaking the others, and each has its own attack surface.
```
