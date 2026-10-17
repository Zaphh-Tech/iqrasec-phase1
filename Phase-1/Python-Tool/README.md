# ioc_extract.py — IOC Extractor

## Tool Name
**ioc_extract.py** — an Indicator-of-Compromise (IOC) extractor.

## Objective
Pull the useful indicators out of messy security text — logs, threat-intel reports,
phishing emails, pastes — automatically. It finds IPs, domains, URLs, emails, file
hashes and CVE IDs, de-duplicates them, and prints them grouped or as JSON/CSV so they
can feed straight into a blocklist, a ticket, or another tool. It understands
**defanged** indicators (`hxxp://`, `1[.]2[.]3[.]4`, `user[at]evil[.]com`) so IOCs copied
out of reports are still caught, and can **defang its own output** so results are safe to
share.

## Features
- A magnifier **logo banner** printed to *stderr* — visible on a terminal, never corrupts JSON/CSV piped on stdout (hidden by `-q`).
- Extracts **IPv4, IPv6, URLs, emails, domains, MD5, SHA1, SHA256, and CVE IDs**.
- **Refangs** input automatically (`hxxp`→`http`, `[.]`→`.`, `[at]`→`@`) before scanning.
- **De-duplicates**, normalises case, and sorts every indicator.
- Three output formats: **text** (grouped), **JSON**, **CSV**.
- `--types` to extract only the kinds you want (e.g. `sha256,url`).
- `--defang` to make output safe to paste; `--no-private` to drop RFC1918/loopback IPs.
- Reads a **file** or **standard input** (pipe-friendly).
- Separates domains from URL hosts / email hosts and filters out filenames
  (`sample.exe`, `gate.php`) to cut false positives.
- Built from **functions**, with argparse help and clear error handling.
- Exit code **0** if IOCs were found, **3** if none — scriptable.

## Requirements
- **Python 3.6+**. Standard library only (`re`, `argparse`, `json`, `csv`) — no `pip`.

## How to Run
```bash
chmod +x tool.py
./tool.py report.txt                 # extract everything from a file
cat alerts.log | ./tool.py           # or read from stdin
./tool.py --help                     # all options
./tool.py --version                  # 1.1
./tool.py report.txt -q              # suppress the logo banner
```

## Example Usage
```bash
./tool.py report.txt --types ipv4,sha256 --no-private     # only external IPs + SHA256
./tool.py report.txt --format json -o iocs.json           # JSON to a file
cat email.eml | ./tool.py --types url,domain --defang     # safe-to-share output
./tool.py report.txt --format csv > iocs.csv              # CSV for a spreadsheet
```

## Example Output
Input (excerpt): `hxxp://evil-domain[.]com/gate.php`, `185.220.101.45`, a SHA256,
`admin[at]evil-domain[.]com`, `CVE-2026-1337`.

```
[IPV4]  (2)
  10.0.0.5
  185.220.101.45

[URL]  (1)
  http://evil-domain.com/gate.php

[EMAIL]  (1)
  admin@evil-domain.com

[DOMAIN]  (2)
  evil-domain.com
  login.evil-cdn.net

[SHA256]  (1)
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

[CVE]  (2)
  CVE-2021-44228
  CVE-2026-1337

Total IOCs: ...
```
JSON (`--types ipv4,sha256 --no-private --format json`):
```json
{
  "ipv4": ["185.220.101.45"],
  "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
}
```
*(See `screenshots/` for full captures.)*

## Challenges Faced
- **Domains overlap with URLs and emails.** A naive domain regex re-reports the host of
  every URL and email, and also matches filenames like `report.txt` / `gate.php`. The tool
  strips URL/email hosts from the domain set and filters a list of file extensions.
- **Defanged indicators.** Report authors defang IOCs so they aren't clickable, which
  breaks plain regexes. A `refang()` step normalises the common conventions first, and a
  `defang()` step lets the output be shared safely.
- **No-input hang.** Reading stdin with no pipe would hang forever, so the tool checks
  `isatty()` and prints a clear error telling the user to pass a file or pipe input.
- **False-positive hashes.** 32/40/64-hex regexes can catch unrelated hex blobs; scoping
  to word boundaries and lower-casing for dedup keeps the output clean and comparable.

## Future Improvements
- Private-range handling for **IPv6** as well as IPv4.
- Optional **IOC validation** (valid TLD list, hash length sanity, CVE year range).
- A `--stix`/`--misp` export mode for direct ingestion into threat-intel platforms.
- Confidence scoring and basic **context** (the line each indicator came from).
