# Phase 01 — Session 02: Example Solution
## setup-env.sh — Annotated Fix

---

## Diff — Broken vs Hardened

```diff
  #!/bin/bash
- # setup-env.sh — sets up a "deployment environment"
+ # setup-env.sh — hardened deployment environment setup

  mkdir -p /opt/app /opt/shared /tmp/uploads

- cp /bin/bash /opt/app/support-tool
- chmod 4755 /opt/app/support-tool        # SUID bash copy
+ # REMOVED: SUID bash copy
+ # A SUID copy of bash runs as root for anyone who executes it.
+ # /opt/app/support-tool -p → immediate root shell for any user on the system.
+ # If a support tool is genuinely needed, build it purpose-specific without SUID.

- chmod 777 /opt/shared                   # world-writable shared dir
+ chmod 1777 /opt/shared
+ # 777 allows any user to delete any other user's files in the directory.
+ # 1777 (sticky bit) keeps world-writable access but restricts deletion:
+ # a user can only delete files they own. This is the same model as /tmp.

- chmod 777 /tmp/uploads
+ chmod 1770 /tmp/uploads
+ chown root:appgroup /tmp/uploads
+ # Uploads only need to be writable by the app group — not every user on the system.
+ # 1770 = owner+group full access, sticky bit, others: nothing.

- # Give the app user write access to logs
- chmod 777 /var/log/app.log
+ touch /var/log/app.log
+ chown appuser:appgroup /var/log/app.log
+ chmod 640 /var/log/app.log
+ # 640: appuser can read+write, appgroup can read, others: nothing.
+ # 777 on a log file lets any user truncate it (evidence destruction) or
+ # inject fake log entries (log poisoning).

- # World-writable .env file
- cat > /opt/app/.env << 'EOF'
- DB_PASSWORD=prod-secret-password
- API_KEY=sk-live-abc123
- EOF
- chmod 666 /opt/app/.env
+ # REMOVED: .env file with credentials
+ # Secrets must never be stored as world-readable files on the filesystem.
+ # Use: environment variables injected at runtime, a secrets manager
+ # (AWS Secrets Manager, Vault, K8s Secrets), or a credential helper.
+ # 666 = any user on the system can read DB_PASSWORD and API_KEY.

- # Passwordless sudo for the deployment user  
- echo "deploy ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
+ # REMOVED: unrestricted passwordless sudo
+ # NOPASSWD:ALL is identical to giving deploy a root shell.
+ # If specific commands need elevated privilege, grant only those:
+ echo "deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp" >> /etc/sudoers
+ # Verify syntax before saving — a broken sudoers file locks out all sudo:
+ visudo -c -f /etc/sudoers
```

---

## Hardened Script

```bash
#!/bin/bash
# setup-env.sh — hardened deployment environment setup
set -euo pipefail   # exit on error, undefined var, or pipe failure

APP_USER="appuser"
APP_GROUP="appgroup"

# Create directories with appropriate permissions
mkdir -p /opt/app /opt/shared /tmp/uploads

# Shared directory: sticky bit prevents cross-user deletion
chmod 1777 /opt/shared

# Upload directory: app group only, sticky bit
chown root:${APP_GROUP} /tmp/uploads
chmod 1770 /tmp/uploads

# Log file: app user owns it, group can read, others cannot
touch /var/log/app.log
chown ${APP_USER}:${APP_GROUP} /var/log/app.log
chmod 640 /var/log/app.log

# App directory: owned by app user, no world access
chown -R ${APP_USER}:${APP_GROUP} /opt/app
chmod 750 /opt/app

# Sudo: only the specific command needed, not ALL
echo "${APP_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp" >> /etc/sudoers
visudo -c   # verify sudoers syntax — fails loudly rather than silently corrupting
```

---

## Privilege Escalation Demo — Before and After

```bash
# ── Setup: run the BROKEN script in a test environment ───────────────────────
sudo bash setup-env-broken.sh

# Switch to www-data (low-privilege attacker starting point)
su - www-data

# PATH 1: SUID bash copy → instant root
/opt/app/support-tool -p
# -p flag: preserve effective UID (root due to SUID)
id
# uid=33(www-data) gid=33(www-data) euid=0(root)  ← root effective UID

# PATH 2: world-writable .env → credential theft (no shell needed)
cat /opt/app/.env
# DB_PASSWORD=prod-secret-password
# API_KEY=sk-live-abc123

# PATH 3: world-writable log → evidence destruction
truncate -s 0 /var/log/app.log
echo "[INFO] Nothing suspicious happened" >> /var/log/app.log
# Attacker can overwrite logs covering their tracks

# ── Verify HARDENED script blocks all three paths ─────────────────────────────
sudo bash setup-env-hardened.sh
su - www-data

# PATH 1: SUID binary gone
ls -la /opt/app/support-tool 2>&1
# ls: cannot access '/opt/app/support-tool': No such file or directory

# PATH 2: .env not world-readable
cat /opt/app/.env 2>&1
# cat: /opt/app/.env: No such file or directory  (or: Permission denied)

# PATH 3: log not world-writable
truncate -s 0 /var/log/app.log 2>&1
# truncate: cannot open '/var/log/app.log' for writing: Permission denied
```

---

## Key Verification Commands

```bash
# Find ALL SUID binaries on the system (run regularly)
find / -perm -4000 -type f 2>/dev/null
# Expected in hardened system: only known binaries (passwd, sudo, ping, newgrp)
# Anything unexpected = finding

# Find world-writable files outside /tmp (should be empty in a hardened system)
find / -perm -0002 -type f 2>/dev/null | grep -v "^/tmp" | grep -v "^/proc"

# Find world-writable directories
find / -perm -0002 -type d 2>/dev/null | grep -v "^/proc" | grep -v "^/sys"

# Audit sudoers for NOPASSWD entries
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null
# Any line with NOPASSWD:ALL is a finding

# Check sticky bit on shared directories
stat /opt/shared /tmp/uploads | grep "Access:"
# Look for the 't' in the permissions: drwxrwxrwt (1777)

# Verify no credentials in world-readable files
find /opt /var /home -name "*.env" -o -name "*.conf" -o -name "*.cfg" 2>/dev/null \
  | xargs ls -la 2>/dev/null | grep -v "^-[rwx-][rwx-][rwx-]...[^-]"
```

---

## 3-Line Session Summary

```
Covered:   SUID binaries, world-writable files/dirs, sticky bit, sudoers misconfiguration
           — four independent privilege escalation paths in one deployment script.
Diagnosed: www-data → root in one command via SUID bash copy;
           credential theft via world-readable .env without any exploit.
Key shift: chmod 777 is the developer's shortcut for "this works now";
           the attacker reads it as "I can write here."
```
