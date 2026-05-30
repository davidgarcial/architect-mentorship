# Session 03 — Case Study

> Real container-escape and capability-abuse incidents. Read AFTER completing the exercise.

---

## Incident 1: Tesla Kubernetes Cluster Cryptojacking (2018)

**What happened:** Researchers at RedLock found that Tesla's internal Kubernetes cluster — running on AWS — was completely unauthenticated. Attackers had taken it over and were mining cryptocurrency. They also had access to AWS credentials and proprietary engineering data (telemetry, mapping data).

**Root cause:** Tesla's Kubernetes dashboard was exposed to the internet without authentication. Once an attacker reached the dashboard, they could deploy any pod with any capabilities to any node — including pods with `privileged: true`, `hostNetwork: true`, and `hostPID: true`. Container isolation became irrelevant.

**Why container isolation didn't save them:** Container isolation prevents processes inside a normal container from affecting the host. But a privileged container or a container with `hostPID` is not isolated — it's running on the host kernel with full visibility. Privileged → effectively root on the node.

**Which control prevents it:**
- **Authentication on the Kubernetes API** — non-negotiable; never expose unauthenticated
- **Pod Security Standards** with `restricted` profile cluster-wide — denies privileged, hostPath, hostNetwork, hostPID by default
- **Network Policy** to isolate the cluster from internet
- **OPA Gatekeeper / Kyverno** policies to deny `--privileged` at admission

**How to test your cluster today:**
```bash
# Are any of your pods privileged? They almost always shouldn't be.
kubectl get pods --all-namespaces -o jsonpath='{range .items[?(@.spec.containers[?(@.securityContext.privileged==true)])]}{.metadata.namespace}{"/"}{.metadata.name}{"\n"}{end}'

# Are any using hostNetwork or hostPID?
kubectl get pods --all-namespaces -o yaml | grep -E 'hostNetwork: true|hostPID: true' -B5

# Is your dashboard exposed?
kubectl get svc -n kubernetes-dashboard 2>/dev/null
```

**Architect's lesson:** "Internal" Kubernetes APIs become external the moment they're exposed via a LoadBalancer Service or a misconfigured Ingress. Treat the K8s API server as a public endpoint and design accordingly.

---

## Incident 2: runc Container Escape — CVE-2019-5736 (February 2019)

**What happened:** Aleksa Sarai disclosed that runc (the container runtime under Docker, Kubernetes, and most container platforms) could be tricked into overwriting itself, allowing a malicious container to break out and gain root on the host.

**Root cause:** When runc invoked a process inside a container, it used `/proc/self/exe` to re-exec itself. A malicious container could open `/proc/self/exe`, write to it, and overwrite the host's runc binary. Next time anyone started a container, the attacker's code ran on the host.

**Capabilities involved:** None special — the exploit worked from any container started as root (default in many setups). It did NOT require `CAP_SYS_ADMIN` or `--privileged`. It only required the host to use a vulnerable version of runc.

**Why "non-privileged" containers weren't safe:** "Non-privileged" only means you don't have `CAP_SYS_ADMIN`. It does NOT mean you're isolated from the host kernel's filesystem. Container processes share `/proc` (with namespace filtering), and `/proc/self/exe` can be abused.

**Which control prevents it:**
- **Patching runc** — Docker 18.09.2+, Kubernetes images updated
- **Running containers as non-root** — even if the bug exists, a non-root container can't write to `/proc/self/exe`
- **User namespaces** — map container root to a non-root host UID
- **Read-only root filesystem** (`readOnlyRootFilesystem: true`)

**How to test today:**
```bash
# Check runc version on every node
docker version | grep runc            # if Docker host
runc --version                        # bare runc

# Make sure all your pods run as non-root
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{": runAsUser="}{.spec.containers[0].securityContext.runAsUser}{"\n"}{end}' | grep -v "runAsUser=[0-9]"
```

**Architect's lesson:** Container security depends on the entire chain — runtime (runc, containerd, Docker), kernel, capabilities, and user context. A bug anywhere in that chain becomes a host compromise. Defense in depth: non-root user, read-only filesystem, minimal capabilities, MAC profile.

---

## Incident 3: CVE-2022-0492 — cgroups v1 release_agent Container Escape

**What happened:** Yiqi Sun & Kevin Wang (Unit 42) disclosed an escape that worked against containers with `CAP_SYS_ADMIN` (commonly given for "convenience" by ops teams who didn't understand the implications). It also worked for unprivileged user namespaces in some configurations.

**Root cause:** cgroups v1 had a `release_agent` file. When the last process in a cgroup exited, the kernel would execute the program named in `release_agent` — as root on the host. Containers with `CAP_SYS_ADMIN` could mount a cgroups filesystem, write to `release_agent`, and trigger arbitrary host code execution.

**Capability involved:** `CAP_SYS_ADMIN` — the "Swiss army knife of capabilities," frequently given to make `docker run --privileged` work for development.

**Which control prevents it:**
- **Don't grant `CAP_SYS_ADMIN`** (almost never necessary in production)
- **Don't run with `--privileged`** in production
- **Use cgroups v2** (not vulnerable — no `release_agent`)
- **AppArmor/SELinux profile** denying writes to cgroup filesystems

**Architect's lesson:** `CAP_SYS_ADMIN` is approximately equivalent to root on the host. Every `--privileged` container in your fleet is one bug away from full node compromise.

---

## Reading

- Tesla cryptojacking report (RedLock 2018) — search "Tesla Kubernetes Cryptojacking"
- runc CVE-2019-5736 advisory: https://seclists.org/oss-sec/2019/q1/119
- CVE-2022-0492 Unit 42 writeup: https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/
- Capabilities man page: `man 7 capabilities`
- GTFOBins capabilities section: https://gtfobins.github.io/#+capabilities
