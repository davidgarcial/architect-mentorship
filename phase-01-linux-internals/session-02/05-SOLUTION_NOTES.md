# Phase 01 — Session 02: Solution Notes
## File Permissions, setuid/setgid, Sticky Bit

### Conceptual Answers

**Why does setuid on a binary give you the file owner's privileges?**
The kernel checks the setuid bit at `execve()` time. When set, the kernel sets the process's *effective UID* to the file owner's UID regardless of who invoked it. The kernel then uses effective UID for all permission checks during the process's lifetime. This is how `passwd` can write `/etc/shadow` (owned by root) even when invoked by a normal user.

**Why is setuid on scripts almost universally ignored by the Linux kernel?**
The kernel disables setuid on interpreted scripts (anything with a shebang `#!`) because of a TOCTOU race: between the kernel checking the bit and the interpreter opening the file, an attacker can swap the file for a malicious one. Most Linux kernels simply clear setuid on scripts at execve time. On older systems or with certain configurations (FreeBSD) this can be exploited.

**What does the sticky bit on a directory actually prevent?**
In a world-writable directory (like `/tmp`), without the sticky bit any user can delete any other user's files (ownership of the directory allows unlinking). The sticky bit (`chmod +t`) restricts unlinking: you can only delete files you own. This is why `/tmp` has mode `1777` — world-writable but sticky.

### Key Commands
```bash
# Find all setuid binaries on the system
find / -perm -4000 -type f 2>/dev/null

# Find all setgid binaries
find / -perm -2000 -type f 2>/dev/null

# Find world-writable directories (classic persistence spots)
find / -perm -0002 -type d 2>/dev/null | grep -v proc

# Inspect a specific binary
ls -la /usr/bin/passwd
# -rwsr-xr-x 1 root root ...
# The 's' in owner execute position = setuid set

# Check capabilities instead of setuid (modern approach)
getcap -r / 2>/dev/null

# Remove setuid from a binary
chmod u-s /path/to/binary
```

### Exploit Chain: setuid + writable PATH
```
Attacker finds /usr/local/bin/backup owned by root with setuid bit
→ backup script calls `tar` without absolute path
→ attacker creates /tmp/tar with content: /bin/bash -p
→ attacker prepends /tmp to PATH: export PATH=/tmp:$PATH
→ runs /usr/local/bin/backup
→ kernel exec's backup as root (setuid)
→ backup's tar call resolves to /tmp/tar
→ /bin/bash -p runs — -p flag preserves effective UID (root)
→ attacker has root shell
```

### Evidence It Works
- `find / -perm -4000` finds `passwd`, `sudo`, `ping`, `newgrp` — this is expected
- Any unexpected binary (a backup script, a custom tool) in that list = finding
- After adding sticky bit to a shared dir: `stat /shared | grep Uid` shows `1777`
- Another user's files cannot be deleted: `rm /shared/other-user-file` → "Operation not permitted"

### Common Mistakes
- Confusing setuid bit (4000) with sticky bit (1000) — remember: setuid=4, setgid=2, sticky=1
- Not checking capabilities (`getcap`) — modern systems use capabilities instead of setuid for many tools, but `getcap -r /` is just as important as `find -perm -4000`
- Missing setuid on directories: `find -perm -4000 -type d` catches setuid directories which behave differently from files
