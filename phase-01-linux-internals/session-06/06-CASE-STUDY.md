# Session 06 — Case Study

> Real incidents where missing or wrong cgroup limits enabled denial-of-service, resource exhaustion attacks, or quiet credential theft.

---

## Incident 1: Cryptojacking via Unbounded Containers (Tesla, Coinhive, ongoing)

**What happened:** In the Tesla 2018 K8s compromise (covered in Session 03 / 05 case studies), attackers deployed cryptojacking pods with NO `resources` block. The pods consumed every available CPU cycle on the node — slowing legitimate workloads and increasing AWS bills by orders of magnitude.

**Root cause:** Default K8s pods have no CPU or memory limits. A scheduler will admit them, the kernel will give them everything available. In a multi-tenant cluster, one greedy pod starves every other workload on the node.

**Why this is a security issue (not just operational):** In multi-tenant or co-tenant environments, "resource exhaustion of co-tenant" IS a security boundary violation. SLAs guaranteed to tenant A are broken by tenant B's lack of limits. In SaaS environments with shared infrastructure, this enables "noisy neighbor" attacks.

**Architect's lesson:** `limits` and `requests` on every pod are a security requirement in multi-tenant environments. They are not just for capacity planning.

---

## Incident 2: Fork Bomb DOS (Multi-Tenant SaaS, 2019-2020)

**What happened:** A SaaS provider running customer code in shared K8s pods had no `pids` limit on containers. A malicious tenant ran a fork bomb (`:(){ :|:& };:`) and exhausted the host's PID space — preventing the kubelet from spawning new processes, breaking the node, and taking down every co-tenant.

**Root cause:** The cluster's PodSecurityContext didn't enforce `pids.max`. Without this cgroup limit, a process inside a container can fork unbounded.

**Which control prevents it:**
- `resources.limits.pids` (note: not as commonly known as cpu/memory limits)
- LimitRange in the namespace enforcing pid limits
- Node-level pids.max via kubelet config

**How to check today:**
```bash
# Find pods with NO pid limit (they're vulnerable to fork bombs)
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(.spec.containers[] | (.resources.limits.pids // null) == null) |
  "\(.metadata.namespace)/\(.metadata.name)"
' | head
```

---

## Incident 3: Memory Limit Bypass via mmap (CVE-class, recurring)

**What happened:** Multiple disclosures (CVE-2020-14386, CVE-2021-22555, others) involve cgroup memory accounting bypasses — an attacker process uses `mmap` with specific flags to allocate memory that's NOT charged to the cgroup. Bypasses memory limits, OOM-kills become unreliable.

**Architect's lesson:** Memory limits are best-effort, not absolute. In multi-tenant clusters, defense in depth is required: cgroup limits + kernel memory accounting + Linux memory pressure events + Pod Disruption Budget for critical workloads.

---

## Incident 4: Quiet Credential Exfiltration via Resource Patterns (Detection Gap)

A subtle case from a 2022 IR engagement (published anonymized by Mandiant): an attacker who had compromised a developer machine launched a Kubernetes Job that used very low resource usage (under 5% CPU, < 100MB RAM) but ran for weeks, slowly copying data out via DNS exfiltration.

The Job had no `resources` block. The cluster admin had no alerting on "long-running jobs with no resources defined." The job was invisible until a routine audit caught it.

**Architect's lesson:** Resource governance is also a detection mechanism. Pods with anomalous resource patterns (very low usage, very long lifetime) are suspicious. Pods with NO resource declarations are unauditable.

---

## Reading

- "PodSecurityStandards" K8s docs: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- "Resource Quotas" K8s docs: https://kubernetes.io/docs/concepts/policy/resource-quotas/
- cgroups v2 documentation: https://www.kernel.org/doc/Documentation/cgroup-v2.txt
- "Why your K8s pods need limits" — Kubecost blog
