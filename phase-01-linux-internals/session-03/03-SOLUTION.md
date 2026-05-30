# Phase 01 — Linux Deep Internals | Session 03 of 12 -- My Solution

> **Complete this file BEFORE opening 05-SOLUTION_NOTES.md.**
> Attempting the exercise yourself is the entire point. Opening the notes file first turns a hands-on lab into a reading exercise.

---

## Finding 1: SYS_ADMIN
**Location:**  SYS_ADMIN
**What it is:** Too much privilenges 
**Exploit chain:** A container with SYS_ADMIN can: mount /dev/sda1 /mnt → host filesystem insmod malicious.ko  → arbitrary kernel code execution
**Impact:** No application should ever need SYS_ADMIN insmod rootkit.ko   # game over — owns the kernel
**Fix:** Remove it

## Finding 2: SYS_PTRACE
**Location:** SYS_PTRACE
**What it is:** Configure interfaces, routes, iptables, packet capture
**Exploit chain:** Exec ptrace
**Impact:** read memory of any process on the node, including secrets in-flight (TLS keys, passwords, tokens).
**Fix:** Remove it

## Finding 3: NET_ADMIN
**Location:** NET_ADMIN
**What it is:**  allows: modifying routing tables and network
**Exploit chain:** changing firewall rules (iptables)
**Impact:** read all network traffic in the node exposing all the containers
**Fix:** Remove it

## Finding 4: DAC_OVERRIDE
**Location:** DAC_OVERRIDE
**What it is:** can read /etc/shadow, any private key
**Exploit chain:** udate, read or delete all regardless of file permissions
**Impact:** expose all secrets without any controll access
**Fix:** Remove it

---

## Session Summary

Session complete.
Covered: [fill in]
Key insight: [fill in - the one thing that changed how you think]
Gap identified: [fill in - where did you get stuck or miss something?]



docker run -d \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --security-opt seccomp=./seccomp-node.json \
  --read-only \
  --tmpfs /tmp:size=50m,noexec \
  --tmpfs /var/tmp:size=10m,noexec \
  -p 3000:3000 \
  --name nodeapp \
  nodeapp:latest