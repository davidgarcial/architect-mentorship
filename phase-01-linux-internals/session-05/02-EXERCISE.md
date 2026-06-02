# Phase 01 — Linux Deep Internals | Session 05 of 12 — Exercise Artifact

> Work with this artifact directly. Full instructions and background are in 01-README.md.

---

## The Artifact
A `docker-compose.yml` with two services. The `app` service is a normal containerized Node.js application with proper network and volume isolation. The `monitor` service is presented as a "sidecar monitoring agent" but has three flags that each independently destroy namespace isolation: `pid: "host"`, `network_mode: "host"`, and a `/proc` volume mount. Together, they create a container from which an attacker can observe and interact with every process and network connection on the node.

```yaml
version: '3.8'
services:
  app:
    image: node:18-alpine
    networks:
      - internal
    volumes:
      - app-data:/data
    command: node server.js

  monitor:
    image: ubuntu:22.04
    pid: "host"
    network_mode: "host"
    cap_add:
      - SYS_PTRACE
    volumes:
      - /proc:/host-proc:ro
    command: sleep infinity

networks:
  internal:

volumes:
  app-data:
```

This pattern appears in real environments as "observability sidecars," "log collectors," and "health check agents." The security implication is the same regardless of the stated purpose.
