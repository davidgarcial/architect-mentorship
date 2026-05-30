# Phase 01 — Linux Deep Internals | Session 03 of 12 — Exercise Artifact

> Work with this artifact directly. Full instructions and background are in 01-README.md.

---

## The Artifact
A Dockerfile for a Node.js application that is structured correctly on its own — it uses a non-root user and installs only what it needs. The danger is entirely in how it is run. The `docker run` command adds four capabilities that each independently enable serious attacks, and the combination enables near-total host compromise.

**Dockerfile:**
```dockerfile
FROM node:18-alpine
RUN apk add --no-cache libcap
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
USER node
CMD ["node", "server.js"]
```

**docker run command used in production:**
```bash
docker run -d \
  --cap-add=SYS_ADMIN \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_PTRACE \
  --cap-add=DAC_OVERRIDE \
  myapp:latest
```

Your task: for each capability, explain precisely what kernel operations it unlocks, build a concrete exploit chain showing how an attacker with code execution inside this container would use it, and identify which combinations are particularly dangerous together.
