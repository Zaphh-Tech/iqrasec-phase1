# IqraSec Academy — Scripting & Automation (Phase 1)

Two self-contained cybersecurity automation tools — one Bash, one Python. Both are
defensive and operate only on the local machine or on text you give them; neither makes
any network connection, so they are safe to run and demo on your own system.

## Tools

| Tool | Language | What it does |
|------|----------|--------------|
| [`seccheck.sh`](Phase-1/Bash-Tool/) | Bash | Read-only Linux host security audit — accounts, SSH, SUID, world-writable files, open ports, cron, firewall, updates. Reports PASS/WARN/FAIL/INFO. |
| [`ioc_extract.py`](Phase-1/Python-Tool/) | Python | IOC extractor — pulls IPs, domains, URLs, emails, hashes and CVE IDs out of logs/reports, refangs input, outputs text/JSON/CSV. |

## Structure

```
Phase-1/
├── Bash-Tool/
│   ├── tool.sh          # seccheck.sh — Linux Security Checker
│   ├── README.md
│   └── screenshots/
└── Python-Tool/
    ├── tool.py          # ioc_extract.py — IOC Extractor
    ├── README.md
    ├── examples/        # a sample report to test against
    └── screenshots/
```

## Quick start

```bash
# Bash — audit this host
cd Phase-1/Bash-Tool && chmod +x tool.sh && ./tool.sh

# Python — extract IOCs from the bundled sample
cd Phase-1/Python-Tool && chmod +x tool.py && ./tool.py examples/sample_report.txt
```

Each tool has its own README with full usage, example output, challenges faced and future
improvements. Run either with `--help` / `-h` for all options.

## Safety

These tools are for systems you own or are explicitly authorized to test. The host checker
only reads; the IOC extractor only parses local text. No exploitation, no network traffic.
