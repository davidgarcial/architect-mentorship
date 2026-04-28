# Phase 01 — Linux Deep Internals | Session 02 of 12 — Exercise Artifact

> Work with this artifact directly. Full instructions and background are in 01-README.md.

---

## The Artifact
A shell script (`setup-env.sh`) that a developer wrote to "quickly stand up a deployment environment." It creates directories, installs a support tool, and configures sudo. Every decision in it is wrong from a security standpoint. Your job is to run it in a test environment (a fresh VM or an unprivileged Docker container with `--privileged`), then switch to a `www-data` account and determine how far you can escalate privilege from there.

The script does four things: copies `/bin/bash` to a known path and sets the SUID bit on it, creates world-writable shared directories, makes a world-writable `.env` file, and adds a broad passwordless sudo entry. None of these are individually unusual in real deployment scripts — which is exactly the problem.

```bash
#!/bin/bash
# setup-env.sh — sets up a "deployment environment"
mkdir -p /opt/app /opt/shared /tmp/uploads
cp /bin/bash /opt/app/support-tool
chmod 4755 /opt/app/support-tool        # SUID bash copy
chmod 777 /opt/shared                   # world-writable shared dir
chmod 777 /tmp/uploads                  # world-writable uploads
echo "deploy ALL=(ALL) NOPASSWD: /opt/app/support-tool" >> /etc/sudoers
touch /opt/shared/.env
chmod 666 /opt/shared/.env             # world-writable env file
```

Run this as root. Then switch to `www-data` (or any low-privilege user) and treat the system as an attacker would.
