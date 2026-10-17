#!/usr/bin/env python3
"""
ioc_extract.py — IOC Extractor

Pulls Indicators of Compromise (IOCs) out of any text: logs, threat-intel reports,
phishing emails, pastes. It finds IPv4/IPv6 addresses, domains, URLs, email
addresses, file hashes (MD5/SHA1/SHA256) and CVE IDs, de-duplicates them, and
prints them grouped — or as JSON / CSV for feeding into other tools.

It also understands *defanged* indicators (hxxp://, 1[.]2[.]3[.]4, user[at]evil[.]com)
so IOCs copied out of reports are still caught, and can defang its own output so the
results are safe to paste around.

Reads a file (positional argument) or standard input. It only processes text you give
it — it makes no network connections.

Author: <your name>  |  IqraSec Academy Phase 1
"""

import argparse
import csv
import io
import json
import re
import sys

__version__ = "1.1"


def banner():
    """Print the tool's logo (a magnifier = search) to STDERR.

    Deliberately stderr, so it never corrupts JSON/CSV piped on stdout. Shown only
    when stderr is a real terminal; colour is added only then too.
    """
    if not sys.stderr.isatty():
        return
    c = "\033[36m"   # cyan
    y = "\033[33m"   # yellow
    b = "\033[1m"    # bold
    o = "\033[0m"    # reset
    art = f"""{c}   ╭────────────────────────────────────────────────
   │{o}     {b}.-\"\"\"-.{o}     {b}ioc-extract{o}  {y}v{__version__}{o}
{c}   │{o}    {b}/ {c}o o{o} {b}\\{o}    IOC Extractor
{c}   │{o}    {b}\\  {c}^  {o}{b}/{o}    IPs · domains · URLs · hashes · CVEs
{c}   │{o}     {b}'-.-'{o}
{c}   │{o}       {b}\\{o}      signal from the noise
{c}   ╰────────────────────────────────────────────────{o}"""
    print(art, file=sys.stderr)

# --- regular expressions for each IOC type ----------------------------------
# Kept deliberately readable; each is compiled once at import.

RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
# IPv6: compressed or full form (loose but practical).
RE_IPV6 = re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.IGNORECASE)
RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\]\)]+", re.IGNORECASE)
RE_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}\b", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,}\b", re.IGNORECASE
)
RE_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
RE_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# IOC types in display order. (domains/emails interact, handled in extract().)
IOC_TYPES = [
    "ipv4", "ipv6", "url", "email", "domain",
    "md5", "sha1", "sha256", "cve",
]

# TLDs that commonly appear as the tail of a filename and cause false-positive
# "domains" (e.g. report.txt, sample.exe). We drop single-label matches on these.
_FILE_TLDS = {
    "txt", "exe", "dll", "doc", "docx", "pdf", "png", "jpg", "jpeg", "gif",
    "log", "zip", "gz", "tar", "py", "sh", "bin", "dat", "tmp", "csv", "md",
    "php", "html", "htm", "asp", "aspx", "jsp", "js", "css", "json", "xml",
}


def refang(text: str) -> str:
    """Turn defanged indicators back into real ones so the regexes match.

    Handles the common report conventions: hxxp -> http, [.]/(.)/{.} -> ., and
    [at]/(at) -> @, plus [:]/(:) -> :.
    """
    text = re.sub(r"h\s*x\s*x\s*p", "http", text, flags=re.IGNORECASE)
    text = re.sub(r"[\[\(\{]\s*\.\s*[\]\)\}]", ".", text)   # [.] (.) {.}
    text = re.sub(r"[\[\(\{]\s*:\s*[\]\)\}]", ":", text)     # [:] (:)
    text = re.sub(r"[\[\(]\s*(?:at|@)\s*[\]\)]", "@", text, flags=re.IGNORECASE)
    text = re.sub(r"[\[\(]\s*dot\s*[\]\)]", ".", text, flags=re.IGNORECASE)
    return text


def defang(value: str) -> str:
    """Make an indicator safe to paste (the inverse of refang, lightly)."""
    value = value.replace("http", "hxxp")
    value = value.replace(".", "[.]")
    return value


def read_input(path):
    """Return the text to scan, from a file path or stdin. Raises on failure."""
    if path and path != "-":
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    # No path (or "-"): read stdin. Guard against an interactive no-input hang.
    if sys.stdin.isatty():
        raise ValueError("no input: give a FILE argument or pipe text via stdin")
    return sys.stdin.read()


def extract(text, wanted, drop_private=False):
    """Extract IOCs from text.

    Returns a dict {ioc_type: sorted list of unique values}. `wanted` limits the
    types; `drop_private` removes RFC1918 / loopback IPv4 addresses.
    """
    found = {t: set() for t in IOC_TYPES}

    if "ipv4" in wanted:
        for ip in RE_IPV4.findall(text):
            if drop_private and _is_private_v4(ip):
                continue
            found["ipv4"].add(ip)
    if "ipv6" in wanted:
        found["ipv6"].update(RE_IPV6.findall(text))
    if "url" in wanted:
        found["url"].update(RE_URL.findall(text))
    if "email" in wanted:
        found["email"].update(m.lower() for m in RE_EMAIL.findall(text))
    if "md5" in wanted:
        found["md5"].update(h.lower() for h in RE_MD5.findall(text))
    if "sha1" in wanted:
        found["sha1"].update(h.lower() for h in RE_SHA1.findall(text))
    if "sha256" in wanted:
        found["sha256"].update(h.lower() for h in RE_SHA256.findall(text))
    if "cve" in wanted:
        found["cve"].update(c.upper() for c in RE_CVE.findall(text))

    if "domain" in wanted:
        # Domains overlap with URLs and emails; strip those hosts out so a domain
        # isn't double-reported, and drop obvious filenames.
        email_hosts = {e.split("@", 1)[1] for e in found["email"]}
        url_hosts = set()
        for u in found["url"]:
            host = re.sub(r"^\w+://", "", u).split("/", 1)[0].split(":", 1)[0]
            url_hosts.add(host.lower())
        for d in RE_DOMAIN.findall(text):
            dl = d.lower()
            if dl in email_hosts or dl in url_hosts:
                continue
            if dl.rsplit(".", 1)[-1] in _FILE_TLDS:
                continue
            found["domain"].add(dl)

    # Return only requested types, as sorted lists.
    return {t: sorted(found[t]) for t in IOC_TYPES if t in wanted}


def _is_private_v4(ip):
    """True for RFC1918 / loopback / link-local IPv4 (best-effort, stdlib only)."""
    try:
        a, b = (int(x) for x in ip.split(".")[:2])
    except ValueError:
        return False
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or a == 127
        or (a == 169 and b == 254)
    )


def output_text(results, do_defang):
    """Human-readable grouped output."""
    out = []
    total = 0
    for t, values in results.items():
        if not values:
            continue
        total += len(values)
        out.append(f"\n[{t.upper()}]  ({len(values)})")
        for v in values:
            out.append(f"  {defang(v) if do_defang else v}")
    if total == 0:
        return "No IOCs found."
    out.append(f"\nTotal IOCs: {total}")
    return "\n".join(out).lstrip("\n")


def output_json(results, do_defang):
    if do_defang:
        results = {t: [defang(v) for v in vs] for t, vs in results.items()}
    return json.dumps(results, indent=2)


def output_csv(results, do_defang):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "indicator"])
    for t, values in results.items():
        for v in values:
            writer.writerow([t, defang(v) if do_defang else v])
    return buf.getvalue().rstrip("\n")


def build_parser():
    p = argparse.ArgumentParser(
        prog="ioc_extract.py",
        description="Extract IOCs (IPs, domains, URLs, emails, hashes, CVEs) from text.",
        epilog="Examples:\n"
               "  ./tool.py report.txt\n"
               "  cat alerts.log | ./tool.py --types ipv4,url --format json\n"
               "  ./tool.py report.txt --types sha256 --output hashes.csv --format csv\n"
               "  ./tool.py report.txt --defang        # make output safe to paste",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("file", nargs="?", default="-",
                   help="input file (default: read standard input)")
    p.add_argument("-t", "--types", default="all",
                   help="comma-separated types to extract "
                        f"({', '.join(IOC_TYPES)}, or 'all')")
    p.add_argument("-f", "--format", choices=["text", "json", "csv"], default="text",
                   help="output format (default: text)")
    p.add_argument("-o", "--output", help="write results to a file instead of stdout")
    p.add_argument("--defang", action="store_true",
                   help="defang the output (hxxp, [.]) so it is safe to share")
    p.add_argument("--no-refang", action="store_true",
                   help="do NOT refang the input before scanning")
    p.add_argument("--no-private", action="store_true",
                   help="drop private/loopback IPv4 addresses")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="do not print the logo banner")
    p.add_argument("--version", action="version",
                   version=f"ioc_extract.py {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if not args.quiet:
        banner()

    # Resolve the requested IOC types.
    if args.types.strip().lower() == "all":
        wanted = set(IOC_TYPES)
    else:
        wanted = {t.strip().lower() for t in args.types.split(",") if t.strip()}
        bad = wanted - set(IOC_TYPES)
        if bad:
            print(f"error: unknown type(s): {', '.join(sorted(bad))}", file=sys.stderr)
            print(f"valid types: {', '.join(IOC_TYPES)}, all", file=sys.stderr)
            return 2

    # Read input with clear error handling.
    try:
        text = read_input(args.file)
    except FileNotFoundError:
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"error: cannot read file: {args.file}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not args.no_refang:
        text = refang(text)

    results = extract(text, wanted, drop_private=args.no_private)

    renderers = {"text": output_text, "json": output_json, "csv": output_csv}
    rendered = renderers[args.format](results, args.defang)

    # Write to a file or stdout.
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(rendered + "\n")
            print(f"Results written to: {args.output}", file=sys.stderr)
        except OSError as exc:
            print(f"error: cannot write output: {exc}", file=sys.stderr)
            return 1
    else:
        print(rendered)

    # Exit 0 if any IOC was found, 3 if none (handy for scripting).
    return 0 if any(results.values()) else 3


if __name__ == "__main__":
    sys.exit(main())
