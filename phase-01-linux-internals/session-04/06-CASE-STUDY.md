# Session 04 — Case Study

> Real incidents where missing or weak seccomp profiles enabled container escape or kernel exploitation.

---

## Incident 1: Docker's Default Seccomp Profile vs CVE-2017-7308 (af_packet)

**What happened:** In 2017, Andrey Konovalov disclosed a Linux kernel use-after-free in the `af_packet` socket family. Exploitation gave a local attacker root on the kernel. The bug was triggerable from any process that could call `socket(AF_PACKET, ...)`.

**Why it mattered for containers:** Default Docker containers run with CAP_NET_RAW, which allows raw socket creation. A compromised container process could call `socket(AF_PACKET)` and trigger the kernel UAF, escaping the container with full host root.

**Why Docker users were largely safe anyway:** Docker's default seccomp profile blocks several rarely-needed syscalls. While it permits `socket()`, the kernel exploit also relied on `setsockopt()` with specific options that were unusual but not blocked. Containers running with `--security-opt seccomp=unconfined` or with custom profiles that allowed all syscalls were fully vulnerable.

**Architect's lesson:** Docker's default seccomp profile is the result of years of cumulative kernel CVE response. Every blocked syscall is there because of a past attack. Disabling it ("`security_opt: ['seccomp:unconfined']`") removes that accumulated protection. The "convenience" of seccomp=unconfined comes at the cost of every past mitigation.

---

## Incident 2: Capsule Kubernetes Operator Sandbox Escape (CVE-2023-23329, 2023)

**What happened:** The Capsule project (multi-tenant K8s operator) had a flaw where tenant workloads could bypass restrictions because the operator did not enforce strict seccomp profiles for namespace isolation. A malicious tenant could use `ptrace` to attach to neighboring tenant processes if they shared a node — exfiltrating credentials from memory.

**Root cause:** No SeccompProfile in the PodSecurityStandards baseline — tenants could still call `ptrace`, `bpf`, and `unshare` because the default profile in the operator was `Unconfined`.

**Which control prevents it:** PodSecurityStandards `restricted` profile or explicit `securityContext.seccompProfile.type: RuntimeDefault` on every workload.

**How to check your cluster today:**
```bash
# Find pods running with seccomp=Unconfined or no profile at all
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(.spec.securityContext.seccompProfile == null and (.spec.containers[].securityContext.seccompProfile == null)) |
  "\(.metadata.namespace)/\(.metadata.name)"
'
```

---

## Incident 3: Real Strace Forensics — Detecting a Mining Container (2020+)

A common forensic pattern in incident response: an unexplained CPU-heavy container. Defenders attach `strace -p <PID>` to investigate. Discoveries:

- The container is hashing — calls to `read()` on `/dev/urandom` thousands per second
- Massive `connect()` calls to mining pool IPs (185.x.x.x ranges)
- `clone()` calls spawning child threads matching the host's CPU count

`strace` of a single hostile container has prevented hundreds of cryptojacking incidents per Falco maintainer reports. Without it, ops teams see "high CPU" and restart the container.

**Architect's lesson:** strace is not just a debugging tool — it's a runtime detection mechanism. Every architect should know it. Every incident-response runbook should include it.

---

## Reading

- Docker default seccomp profile (source): https://github.com/moby/moby/blob/master/profiles/seccomp/default.json
- Kubernetes seccomp tutorial: https://kubernetes.io/docs/tutorials/security/seccomp/
- CVE-2017-7308 advisory: https://www.kernel.org/pub/linux/kernel/CVE-references
- "What is seccomp and how do I use it?" — Aqua Security blog
