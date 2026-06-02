# Phase 01 — Linux Deep Internals | Session 02 of 12 -- My Solution

> **Complete this file BEFORE opening 05-SOLUTION_NOTES.md.**
> Attempting the exercise yourself is the entire point. Opening the notes file first turns a hands-on lab into a reading exercise.

---

- chmod 777 /opt/shared               
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

