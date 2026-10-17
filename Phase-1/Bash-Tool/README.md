# seccheck.sh — Linux Security Checker

## Tool Name
**seccheck.sh** — a read-only Linux host security checker.

## Objective
Give a quick, honest security snapshot of a Linux machine in one command. It inspects
the misconfigurations that matter most in the real world — privileged accounts, SSH
hardening, SUID binaries, world-writable files, exposed ports, cron persistence,
firewall state and missing updates — and reports each as **PASS / WARN / FAIL / INFO**
so you can see at a glance what needs attention. It **only reads**; it never changes the
system.

## Features
- A colour-coded shield **logo banner** (hidden by `-q`, `--no-color`, or when piped).
- Nine audit sections covering the common Linux hardening gaps.
- Clear, colour-coded `[PASS] / [WARN] / [FAIL] / [INFO]` tags, with a summary tally.
- Flags **non-root UID 0** accounts, **empty passwords**, and **NOPASSWD** sudo rules.
- Checks SSH `PermitRootLogin` / `PasswordAuthentication`.
- Lists **unusual SUID/SGID** binaries (those outside the common set).
- Finds **world-writable** files and services bound to **all interfaces**.
- Enumerates cron jobs, firewall status (ufw/iptables) and pending package updates.
- Run everything, or a **single section** with `-s`.
- Optional **report file** (`-o`), `--quiet`, `--no-color`.
- Returns a **non-zero exit code** when any hard failure is found (CI-friendly).

## Requirements
- Bash 4+ and standard GNU/Linux core utilities (`awk`, `grep`, `find`, `uname`).
- Optional (used if present): `ss` or `netstat`, `ufw`/`iptables`, `apt-get`/`dnf`.
- No third-party packages. **Run as root for the full picture** (shadow, auth, all cron).

## How to Run
```bash
chmod +x tool.sh
./tool.sh                      # full audit to the screen
sudo ./tool.sh -o report.txt   # full audit (root sees more) + save a copy
./tool.sh -s ssh               # only the SSH section
./tool.sh --help               # all options
```

## Example Usage
```bash
./tool.sh --no-color -s accounts     # audit just accounts/privileges
sudo ./tool.sh -o /var/log/seccheck_$(date +%F).txt   # scheduled audit to a dated file
./tool.sh ; echo "exit=$?"           # use the exit code in a script
```

## Example Output
```
   ╭────────────────────────────────────────────────
   │   ▟█████▙    s e c c h e c k  v1.1
   │   █ ╺╋╸ █    Linux Security Checker
   │   ▜█ █▛     read-only host audit · changes nothing
   │    ▜█▛      PASS · WARN · FAIL · INFO
   ╰────────────────────────────────────────────────
    scanned host01 · 2026-10-17 00:05:00

=== Accounts & Privileges ===
  [PASS] Only root has UID 0.
  [INFO] Skipped empty-password check (need root to read /etc/shadow).
  [PASS] No NOPASSWD sudo rules found (or not readable).

=== SSH Hardening ===
  [WARN] PermitRootLogin not set (default may allow root).
  [WARN] PasswordAuthentication not set (default is usually 'yes').

=== Pending Updates ===
  [WARN] 15 package update(s) available (apt).

=== Summary ===
  PASS: 2   WARN: 7   FAIL: 0   INFO: 16
  Result: review the WARN items for hardening opportunities.
```
*(See `screenshots/` for full-run captures.)*

## Challenges Faced
- **Root vs. non-root visibility.** Many checks (shadow, auth logs, full cron, iptables)
  need root. Rather than failing, the tool detects this and clearly marks those checks as
  skipped so the report is never misleading.
- **Portability.** Not every host has `ss`, `ufw` or `apt`. Each section probes for the
  tool it needs with `command -v` and degrades gracefully instead of erroring out.
- **SUID false positives.** A raw SUID list is noisy, so the tool compares against a known
  common set and only surfaces the *unusual* ones, which is what actually warrants review.
- **Safe `set` flags.** Used `set -uo pipefail` for safety but handled individual check
  failures locally so one missing file doesn't abort the whole audit.

## Future Improvements
- A `--json` output mode for piping into dashboards or the Python tool.
- CIS-benchmark mapping (tag each check with its CIS control number).
- Baseline mode: save a run and diff future runs to catch drift (new SUID, new port).
- Per-check severity weighting and a numeric hardening score.
