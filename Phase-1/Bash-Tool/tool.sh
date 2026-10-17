#!/usr/bin/env bash
#
# seccheck.sh — Linux Security Checker
#
# A read-only host security audit. It inspects common Linux misconfigurations and
# hardening gaps (accounts, SSH, SUID binaries, world-writable files, open ports,
# cron, firewall, updates) and prints a clear PASS / WARN / FAIL / INFO report.
#
# It NEVER changes the system — it only reads. Run it on hosts you own or are
# authorized to audit.
#
# Author: <your name>  |  IqraSec Academy Phase 1
# -----------------------------------------------------------------------------

# Fail on unset variables and on errors inside pipelines; keep going on a single
# failed check (we handle those locally) rather than aborting the whole script.
set -uo pipefail

# ---- configuration ----------------------------------------------------------
VERSION="1.1"
OUTPUT=""          # optional report file (-o)
QUIET=0            # suppress the banner (-q)
USE_COLOR=1        # colored output unless --no-color or not a TTY
ONLY_SECTION=""    # run a single section (-s)

# counters for the final summary
PASS=0; WARN=0; FAIL=0; INFO=0

# ---- colors (disabled when not a terminal or --no-color) --------------------
setup_colors() {
    if [[ $USE_COLOR -eq 1 && -t 1 ]]; then
        C_RED=$'\e[31m'; C_YEL=$'\e[33m'; C_GRN=$'\e[32m'
        C_BLU=$'\e[34m'; C_BOLD=$'\e[1m'; C_OFF=$'\e[0m'
    else
        C_RED=""; C_YEL=""; C_GRN=""; C_BLU=""; C_BOLD=""; C_OFF=""
    fi
}

# ---- output helpers ---------------------------------------------------------
# Each result line is tagged so the report is easy to scan and to grep.
line() { printf '%s\n' "$*"; [[ -n "$OUTPUT" ]] && printf '%s\n' "$*" >>"$OUTPUT"; }

pass() { ((PASS++)); line "  ${C_GRN}[PASS]${C_OFF} $*"; }
warn() { ((WARN++)); line "  ${C_YEL}[WARN]${C_OFF} $*"; }
fail() { ((FAIL++)); line "  ${C_RED}[FAIL]${C_OFF} $*"; }
info() { ((INFO++)); line "  ${C_BLU}[INFO]${C_OFF} $*"; }

section() { line ""; line "${C_BOLD}${C_BLU}=== $* ===${C_OFF}"; }

# banner : the tool's logo (a shield = security), shown unless --quiet / --no-color off.
banner() {
    line "${C_GRN}   ╭────────────────────────────────────────────────${C_OFF}"
    line "${C_GRN}   │${C_OFF}   ${C_BOLD}${C_GRN}▟█████▙${C_OFF}    ${C_BOLD}s e c c h e c k${C_OFF}  ${C_YEL}v${VERSION}${C_OFF}"
    line "${C_GRN}   │${C_OFF}   ${C_BOLD}${C_GRN}█ ${C_OFF}${C_BOLD}╺╋╸${C_GRN} █${C_OFF}    Linux Security Checker"
    line "${C_GRN}   │${C_OFF}   ${C_BOLD}${C_GRN}▜█${C_OFF} ${C_BOLD}${C_GRN}█▛${C_OFF}    read-only host audit · changes nothing"
    line "${C_GRN}   │${C_OFF}    ${C_BOLD}${C_GRN}▜█▛${C_OFF}     ${C_BLU}PASS${C_OFF} · ${C_YEL}WARN${C_OFF} · ${C_RED}FAIL${C_OFF} · ${C_BLU}INFO${C_OFF}"
    line "${C_GRN}   ╰────────────────────────────────────────────────${C_OFF}"
}

# have <cmd> : is a command available?
have() { command -v "$1" >/dev/null 2>&1; }

# am_root : is the script running as root? (some checks need it)
am_root() { [[ ${EUID:-$(id -u)} -eq 0 ]]; }

# ---- usage ------------------------------------------------------------------
usage() {
    cat <<EOF
seccheck.sh v${VERSION} — Linux Security Checker (read-only host audit)

USAGE:
    ./tool.sh [options]

OPTIONS:
    -o, --output FILE     Also write the report to FILE
    -s, --section NAME    Run only one section
                          (system|accounts|ssh|suid|worldwrite|ports|cron|firewall|updates)
    -q, --quiet           Do not print the banner
        --no-color        Disable colored output
    -h, --help            Show this help and exit

EXAMPLES:
    ./tool.sh                      # full audit to the screen
    sudo ./tool.sh -o report.txt   # full audit (root sees more) + save to file
    ./tool.sh -s ssh               # only the SSH hardening section

NOTE:
    Only audits the local machine, and only reads — it changes nothing.
    Run as root for the complete picture (shadow, auth logs, all cron).
EOF
}

# ---- sections ---------------------------------------------------------------

check_system() {
    section "System Information"
    info "Hostname : $(hostname 2>/dev/null || echo unknown)"
    info "Kernel   : $(uname -sr 2>/dev/null || echo unknown)"
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        info "OS       : $(. /etc/os-release && echo "$PRETTY_NAME")"
    fi
    info "Uptime   : $(uptime -p 2>/dev/null || echo unknown)"
    info "Running as: $(id -un) (uid $(id -u))"
    am_root || warn "Not running as root — shadow/auth/cron checks will be partial."
}

check_accounts() {
    section "Accounts & Privileges"

    # Any account other than root with UID 0 is a privilege backdoor.
    local uid0
    uid0=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)
    if [[ -n "$uid0" ]]; then
        fail "Non-root accounts with UID 0: $uid0"
    else
        pass "Only root has UID 0."
    fi

    # Empty-password accounts (needs shadow, i.e. root).
    if am_root && [[ -r /etc/shadow ]]; then
        local empty
        empty=$(awk -F: '($2=="" ) {print $1}' /etc/shadow 2>/dev/null)
        if [[ -n "$empty" ]]; then
            fail "Accounts with EMPTY password: $empty"
        else
            pass "No accounts with empty passwords."
        fi
    else
        info "Skipped empty-password check (need root to read /etc/shadow)."
    fi

    # Passwordless sudo is a common foot-gun.
    if grep -rEh '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -q .; then
        warn "Passwordless sudo (NOPASSWD) rules are present."
    else
        pass "No NOPASSWD sudo rules found (or not readable)."
    fi
}

check_ssh() {
    section "SSH Hardening"
    local cfg=/etc/ssh/sshd_config
    if [[ ! -r "$cfg" ]]; then
        info "sshd_config not readable here — skipping."
        return
    fi
    # Read the effective (last, uncommented) value of a directive.
    sshd_val() { grep -iE "^[[:space:]]*$1[[:space:]]" "$cfg" 2>/dev/null | tail -n1 | awk '{print $2}'; }

    local root_login pass_auth
    root_login=$(sshd_val PermitRootLogin)
    pass_auth=$(sshd_val PasswordAuthentication)

    case "${root_login,,}" in
        no|prohibit-password) pass "PermitRootLogin = ${root_login}" ;;
        "")                   warn "PermitRootLogin not set (default may allow root)." ;;
        *)                    fail "PermitRootLogin = ${root_login} (root SSH login allowed)." ;;
    esac

    case "${pass_auth,,}" in
        no)  pass "PasswordAuthentication = no (keys only)." ;;
        "")  warn "PasswordAuthentication not set (default is usually 'yes')." ;;
        *)   warn "PasswordAuthentication = ${pass_auth} (password logins allowed)." ;;
    esac
}

check_suid() {
    section "SUID / SGID Binaries"
    # SUID/SGID binaries run with the owner's privileges; unexpected ones are risky.
    # Bounded to common binary dirs so the scan stays fast.
    local dirs=(/usr/bin /usr/sbin /bin /sbin /usr/local/bin)
    local found
    found=$(find "${dirs[@]}" -xdev -type f -perm /6000 2>/dev/null | sort)
    if [[ -z "$found" ]]; then
        info "No SUID/SGID files found in standard bin directories."
        return
    fi
    local count; count=$(wc -l <<<"$found")
    info "Found ${count} SUID/SGID binaries in standard bin dirs."
    # Flag anything outside the usual expected set.
    local expected='ping|sudo|su|mount|umount|passwd|chsh|chfn|newgrp|gpasswd|pkexec|fusermount|fusermount3|crontab|ssh-agent|unix_chkpwd|sg|expiry|chage|dbus-daemon-launch-helper|polkit-agent-helper-1|write|wall'
    local unusual
    unusual=$(grep -vE "/($expected)\$" <<<"$found")
    if [[ -n "$unusual" ]]; then
        warn "SUID/SGID binaries outside the common set — review these:"
        while IFS= read -r f; do line "         $f"; done <<<"$unusual"
    else
        pass "All SUID/SGID binaries are from the common/expected set."
    fi
}

check_worldwrite() {
    section "World-Writable Files"
    # World-writable files/dirs let any user modify them. Sticky-bit dirs (e.g. /tmp)
    # are expected and excluded.
    local ww
    ww=$(find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -n 50)
    if [[ -z "$ww" ]]; then
        pass "No world-writable files found (first 50 scanned)."
    else
        warn "World-writable files (showing up to 50):"
        while IFS= read -r f; do line "         $f"; done <<<"$ww"
    fi
}

check_ports() {
    section "Listening Network Ports"
    # Every listening port is attack surface; know what is exposed.
    local out=""
    if have ss; then
        out=$(ss -tulnp 2>/dev/null)
    elif have netstat; then
        out=$(netstat -tulnp 2>/dev/null)
    else
        info "Neither 'ss' nor 'netstat' available — skipping."
        return
    fi
    if [[ -z "$out" ]]; then
        info "No listening-socket data returned."
        return
    fi
    local n; n=$(grep -cE 'LISTEN|UNCONN' <<<"$out")
    info "Listening sockets: ${n}"
    # Highlight services bound to all interfaces (0.0.0.0 / ::), i.e. externally reachable.
    local public
    public=$(grep -E '0\.0\.0\.0:|:::|\*:' <<<"$out")
    if [[ -n "$public" ]]; then
        warn "Services listening on ALL interfaces (externally reachable):"
        while IFS= read -r l; do line "         $l"; done <<<"$public"
    else
        pass "No services bound to all interfaces."
    fi
}

check_cron() {
    section "Scheduled Jobs (cron)"
    # Attackers use cron for persistence; list what runs automatically.
    local sysn=0
    if [[ -r /etc/crontab ]]; then
        sysn=$(grep -cvE '^\s*(#|$)' /etc/crontab 2>/dev/null)
    fi
    info "Active lines in /etc/crontab: ${sysn}"
    local dirs=(/etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly)
    local d c
    for d in "${dirs[@]}"; do
        if [[ -d "$d" ]]; then
            c=$(find "$d" -maxdepth 1 -type f 2>/dev/null | wc -l)
            info "$d : ${c} job file(s)"
        fi
    done
    if am_root; then
        info "User crontabs present: $(ls /var/spool/cron/crontabs 2>/dev/null | wc -l) (root view)"
    else
        info "Run as root to enumerate every user's crontab."
    fi
}

check_firewall() {
    section "Firewall"
    if have ufw; then
        local s; s=$(ufw status 2>/dev/null | head -n1)
        if grep -qi 'active' <<<"$s"; then pass "ufw: ${s}"; else warn "ufw: ${s:-inactive}"; fi
    elif have iptables; then
        if am_root; then
            local rules; rules=$(iptables -S 2>/dev/null | grep -cvE '^-P')
            if [[ "${rules:-0}" -gt 0 ]]; then pass "iptables: ${rules} explicit rule(s)."
            else warn "iptables: only default policies, no explicit rules."; fi
        else
            info "iptables present — run as root to read the ruleset."
        fi
    else
        warn "No ufw/iptables found — host may have no firewall."
    fi
}

check_updates() {
    section "Pending Updates"
    # Outdated packages are the most common real-world entry point.
    if have apt-get; then
        local n; n=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')
        if [[ "${n:-0}" -eq 0 ]]; then pass "No pending apt updates (or list not refreshed)."
        else warn "${n} package update(s) available (apt)."; fi
    elif have dnf; then
        local n; n=$(dnf -q check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]')
        if [[ "${n:-0}" -eq 0 ]]; then pass "No pending dnf updates."
        else warn "${n} package update(s) available (dnf)."; fi
    else
        info "No supported package manager detected — skipping."
    fi
}

# ---- summary ----------------------------------------------------------------
summary() {
    section "Summary"
    line "  ${C_GRN}PASS: ${PASS}${C_OFF}   ${C_YEL}WARN: ${WARN}${C_OFF}   ${C_RED}FAIL: ${FAIL}${C_OFF}   ${C_BLU}INFO: ${INFO}${C_OFF}"
    if [[ $FAIL -gt 0 ]]; then
        line "  Result: ${C_RED}issues found — review the FAIL items above.${C_OFF}"
    elif [[ $WARN -gt 0 ]]; then
        line "  Result: ${C_YEL}review the WARN items for hardening opportunities.${C_OFF}"
    else
        line "  Result: ${C_GRN}no failures detected in the checks that ran.${C_OFF}"
    fi
}

run_all() {
    check_system; check_accounts; check_ssh; check_suid
    check_worldwrite; check_ports; check_cron; check_firewall; check_updates
}

# ---- argument parsing -------------------------------------------------------
main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output)  OUTPUT="${2:-}"; [[ -z "$OUTPUT" ]] && { echo "error: -o needs a filename" >&2; exit 2; }; shift 2 ;;
            -s|--section) ONLY_SECTION="${2:-}"; [[ -z "$ONLY_SECTION" ]] && { echo "error: -s needs a section name" >&2; exit 2; }; shift 2 ;;
            -q|--quiet)   QUIET=1; shift ;;
            --no-color)   USE_COLOR=0; shift ;;
            -h|--help)    usage; exit 0 ;;
            *) echo "error: unknown option '$1' (try --help)" >&2; exit 2 ;;
        esac
    done

    setup_colors

    # Prepare the output file if requested (fail early if we can't write it).
    if [[ -n "$OUTPUT" ]]; then
        if ! : >"$OUTPUT" 2>/dev/null; then
            echo "error: cannot write to '$OUTPUT'" >&2; exit 1
        fi
    fi

    if [[ $QUIET -eq 0 ]]; then
        banner
        line "    scanned $(hostname 2>/dev/null) · $(date '+%Y-%m-%d %H:%M:%S')"
    fi

    if [[ -n "$ONLY_SECTION" ]]; then
        case "$ONLY_SECTION" in
            system)     check_system ;;
            accounts)   check_accounts ;;
            ssh)        check_ssh ;;
            suid)       check_suid ;;
            worldwrite) check_worldwrite ;;
            ports)      check_ports ;;
            cron)       check_cron ;;
            firewall)   check_firewall ;;
            updates)    check_updates ;;
            *) echo "error: unknown section '$ONLY_SECTION' (try --help)" >&2; exit 2 ;;
        esac
    else
        run_all
    fi

    summary
    [[ -n "$OUTPUT" ]] && line "" && echo "Report written to: $OUTPUT"

    # Exit non-zero if any hard failure was found (useful in CI / automation).
    [[ $FAIL -gt 0 ]] && exit 1 || exit 0
}

main "$@"
