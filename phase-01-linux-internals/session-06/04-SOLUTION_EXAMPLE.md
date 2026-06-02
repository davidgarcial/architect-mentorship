# Phase 01 — Session 06: Example Solution
## Kubernetes Deployment YAML — Annotated Fix

---

## Diff — Broken vs Hardened

```diff
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: api-service
  spec:
    replicas: 3
    selector:
      matchLabels:
        app: api-service
    template:
      metadata:
        labels:
          app: api-service
      spec:
        containers:
        - name: api
          image: myrepo/api:latest
-         # No resources block
+         resources:
+           requests:
+             memory: "128Mi"
+             cpu: "100m"
+           limits:
+             memory: "256Mi"
+             cpu: "500m"
+         # WHY requests matter:
+         # requests = what Kubernetes reserves on the node for this container.
+         # Without requests: Kubernetes schedules pods without knowing their
+         # footprint. A node can be overcommitted by 10x.
+         # Under load: all containers on the node compete for real CPU/memory.
+         # Without requests, Kubernetes cannot make a scheduling decision —
+         # it places pods randomly.
+         #
+         # WHY limits matter (security):
+         # Without memory limit: a container can allocate all available RAM
+         # on the node → OOMKiller kills OTHER containers (not the offender).
+         # This is a denial-of-service against co-tenant workloads — an
+         # attacker who controls one container can kill everything else on the node.
+         # Without CPU limit: a cryptominer in one container consumes all cores,
+         # starving every other workload on the same node.

        - name: redis-sidecar
          image: redis:7-alpine
-         # No resources block
+         resources:
+           requests:
+             memory: "64Mi"
+             cpu: "50m"
+           limits:
+             memory: "128Mi"
+             cpu: "200m"
+         # Redis without limits: if the app has a memory leak or is under
+         # attack (cache poisoning, large key injection), Redis grows unbounded.
+         # The node OOMKills the API pod (higher priority process) before Redis,
+         # causing the service to go down while the attacker's data persists.
```

---

## Hardened Deployment YAML

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-service
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-service
  template:
    metadata:
      labels:
        app: api-service
    spec:
      # Node-level resource context
      priorityClassName: high-priority   # ensures this pod survives node pressure

      containers:
      - name: api
        image: myrepo/api:1.4.2          # pinned tag, not :latest
        ports:
        - containerPort: 8080
          protocol: TCP
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        # Security context at container level
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1001
          capabilities:
            drop: ["ALL"]
        # Liveness and readiness probes (needed for proper OOM recovery)
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5

      - name: redis-sidecar
        image: redis:7-alpine
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "200m"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 999
          capabilities:
            drop: ["ALL"]
        volumeMounts:
        - name: redis-data
          mountPath: /data

      # Pod-level security context
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault

      volumes:
      - name: redis-data
        emptyDir:
          sizeLimit: "256Mi"    # limits how much the redis data dir can grow

---
# Resource quota at namespace level — enforces limits across ALL pods in namespace
apiVersion: v1
kind: ResourceQuota
metadata:
  name: production-quota
  namespace: production
spec:
  hard:
    requests.cpu: "4"
    requests.memory: "8Gi"
    limits.cpu: "8"
    limits.memory: "16Gi"
    pods: "20"
```

---

## Evidence — Demonstrate the Resource Limit Effect

```bash
# ── Deploy broken version (no limits) ────────────────────────────────────────
kubectl apply -f deployment-broken.yaml

# Observe: Kubernetes has no idea what resources the pod needs
kubectl describe pod -l app=api-service | grep -A5 "Limits\|Requests"
# Output: Limits: <none>  Requests: <none>

# ── Simulate memory exhaustion attack ────────────────────────────────────────
# Run a stress test inside the broken container
kubectl exec -it <api-pod> -c api -- sh -c "
  apt-get install -q -y stress 2>/dev/null
  stress --vm 1 --vm-bytes 2G --timeout 30s &
"
# Watch what happens to OTHER pods on the same node:
kubectl get pods -A -o wide --field-selector spec.nodeName=<node> -w
# Other pods start OOMKilling and restarting — the attacker-controlled container
# killed co-tenant workloads without any exploit

# ── Deploy hardened version ───────────────────────────────────────────────────
kubectl apply -f deployment-hardened.yaml

# Verify limits are set
kubectl describe pod -l app=api-service | grep -A10 "Limits\|Requests"
# api:
#   Limits:   cpu: 500m  memory: 256Mi
#   Requests: cpu: 100m  memory: 128Mi
# redis-sidecar:
#   Limits:   cpu: 200m  memory: 128Mi
#   Requests: cpu: 50m   memory: 64Mi

# ── Simulate memory exhaustion on hardened pod ────────────────────────────────
kubectl exec -it <api-pod> -c api -- sh -c "
  # Try to allocate more than the 256Mi limit
  python3 -c \"x = 'A' * (512 * 1024 * 1024); print(len(x))\"
" 2>&1
# Container is OOMKilled (only this container) — other pods on node unaffected
# k8s restarts the container; node and other workloads remain healthy

# ── LimitRange: enforce defaults for pods that forget to set resources ────────
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: production
spec:
  limits:
  - default:
      memory: "256Mi"
      cpu: "500m"
    defaultRequest:
      memory: "64Mi"
      cpu: "100m"
    type: Container
EOF

# Now even pods without a resources block get sensible defaults applied
kubectl describe limitrange default-limits -n production
```

---

## Resource Limit Security Impact Table

```
Missing limit        | Attack vector                          | Impact
─────────────────────┼────────────────────────────────────────┼─────────────────────────────
memory limit         | Allocate all node RAM                  | OOMKill all co-tenant pods
cpu limit            | Cryptominer / tight loop               | Starve all other workloads
no emptyDir sizeLimit| Write huge files to tmpfs              | Node disk pressure, evictions
no ResourceQuota     | Deploy 1000 pods in namespace          | Node exhaustion across cluster
requests not set     | Scheduler overcommits node             | Cascading OOM under real load
```

---

## 3-Line Session Summary

```
Covered:   cgroup resource limits in Kubernetes — how missing limits on memory
           and CPU create availability attack vectors against co-tenant workloads.
Diagnosed: no memory limit → attacker controls one container and OOMKills
           all other pods on the node without any kernel exploit.
Key shift: resource limits are not just ops hygiene — they are a security
           boundary that prevents one tenant from DoS-ing all others on the node.
```
