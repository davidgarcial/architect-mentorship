# Session 05 — Case Study

> Real incidents where namespace isolation was broken — usually intentionally — and attackers exploited the collapsed boundary.

---

## Incident 1: Datadog Agent Container Breakout (2018)

**What happened:** A penetration tester discovered that misconfigured Datadog agent deployments (with `pid: "host"` and `network_mode: "host"`) could be used by any process inside the agent container to:
- Read environment variables of every host process (`/proc/<PID>/environ`)
- Sniff network traffic from host network namespace (raw sockets)
- Send signals to host processes (via shared PID namespace)

Datadog itself was not breached — but customers who deployed the agent with default permissive config in production effectively gave a third-party container full visibility into their host.

**Root cause:** Convenience over isolation. The Datadog agent legitimately needs SOME host visibility to monitor metrics — but full PID + Network namespace sharing is excessive for what it actually needs.

**Architect's lesson:** "Sidecar pattern" + "host namespace" is a common combination that collapses isolation. Every sidecar needs to justify each namespace it shares.

---

## Incident 2: K8s Privileged Container CVE-2018-1002105 + Tesla (Recap)

In Phase 01 Session 03 you read about Tesla's K8s cryptojacking. The root cause was an exposed dashboard. The *amplification* came from namespace sharing: attackers deployed pods with `hostPID: true`, `hostNetwork: true`, and `hostPath` volumes — collapsing namespace isolation deliberately.

Once you can deploy a pod with `hostPath: /` and a privileged context, the host filesystem is yours. Persistence: write to `/etc/cron.d/`. Credential theft: read `/root/.kube/config`. Lateral movement: read kubelet credentials from `/var/lib/kubelet/`.

**Architect's lesson:** Namespace sharing is a binary decision per namespace type. There is no "a little bit of host PID namespace." If you don't need it, deny it via admission control.

---

## Incident 3: Real-World hostPID Information Disclosure (ongoing)

A frequent finding in K8s pentests: log shipping sidecars (Filebeat, Fluentd, Promtail) deployed with `hostPID: true` for "node-level log collection." This gives the container visibility into every process on the node — including command-line arguments of pods belonging to different tenants.

Common consequences in multi-tenant clusters:
- Read JWT tokens passed as command-line args (a known anti-pattern, but common)
- Read database connection strings passed via env vars (`/proc/<PID>/environ`)
- See workload metadata across tenant boundaries

**Architect's lesson:** Process arguments and environment are NOT secret on shared kernels. If you need namespace sharing, you accept that all process information is shared. Plan accordingly.

---

## Incident 4: User Namespace Privilege Escalation (CVE-2022-0185, recap)

Phase 01 Session 04 covered the kernel UAF triggerable via user namespaces. The key takeaway for THIS session: enabling user namespaces in your cluster (`kubernetes.io/feature-gate UserNamespaces`) gives workloads a powerful primitive — but a kernel CVE in the namespace code can turn that into container escape.

Trade-off:
- **User namespaces ON:** containers run as non-root from host's perspective (defense in depth)
- **User namespaces OFF:** smaller attack surface for kernel namespace bugs

For most teams in 2024+: user namespaces ON, with rapid kernel patching SLA.

---

## Reading

- Datadog agent deployment best practices: https://docs.datadoghq.com/agent/kubernetes/
- Kubernetes Pod Security Standards: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- "Container escape patterns" — Aqua / Sysdig blog
- `man 7 user_namespaces`
