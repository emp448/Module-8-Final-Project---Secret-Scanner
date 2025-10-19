#!/usr/bin/env python3
"""
secrets_scanner.py

A small CLI tool to scan files or directories for common hardcoded secrets using regex patterns.

Features:
 - Accepts a file or directory path
 - Uses curated regex patterns to find secrets (API keys, tokens, private keys, JWTs, etc.)
 - Outputs a JSON or CSV report (and prints to stdout)
 - Logging and argparse CLI
"""

import argparse
import logging
import os
import re
import json
import csv
from datetime import datetime
from typing import List, Dict, Pattern, Tuple

# ----------------------
# Configure logging
# ----------------------
logger = logging.getLogger("secrets_scanner")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
logger.addHandler(handler)

# ----------------------
# Regex patterns to detect secrets
# ----------------------
# NOTE: These patterns are intentionally broad to find likely secrets.
# They will produce false positives; consider adding contextual filtering or entropy checks for production.
PATTERNS: List[Tuple[str, Pattern]] = [
    ("AWS Access Key ID", re.compile(r"\b(AKIA|ASIA|AGPA|A3T|AIDA)[0-9A-Z]{16}\b")),  # AKIA...
    ("AWS Secret Access Key", re.compile(r"(?i)\baws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]?")),  # 40 char
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),  # Google API key prefix
    ("Slack Token", re.compile(r"\b(xox[pboasrs]-[0-9A-Za-z-]{10,})\b")),  # xoxb/xoxp etc.
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),  # JWT-ish
    ("RSA/PRIVATE KEY Block", re.compile(r"-----BEGIN ((RSA|OPENSSH|EC|DSA|PGP) )?PRIVATE KEY-----")),  # private key header
    ("SSH Private Key (openssh)", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
    ("Generic High Entropy (base64)", re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")),  # long base64-like string
    ("Generic API Token (hexlike)", re.compile(r"\b[a-f0-9]{32,}\b")),  # long hex strings
    ("Password assignment", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s]{6,})")),  # password = "..."
]

# ----------------------
# Utility functions
# ----------------------
def is_text_file(path: str) -> bool:
    """
    Heuristic: try to open and read a bit as text. If it decodes, treat as text.
    """
    try:
        with open(path, "rb") as f:
            chunk = f.read(4096)
        chunk.decode("utf-8")
        return True
    except Exception:
        return False

def scan_file(path: str, patterns: List[Tuple[str, Pattern]]) -> List[Dict]:
    """
    Scan a single file and return a list of findings as dictionaries:
    {filename, line_no, pattern_name, match}
    """
    findings = []
    try:
        # Try utf-8, fallback to latin-1 to avoid crashes
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for idx, line in enumerate(fh, start=1):
                for pname, pre in patterns:
                    for m in pre.finditer(line):
                        match_text = m.group(0)
                        findings.append({
                            "filename": path,
                            "line": idx,
                            "pattern": pname,
                            "match": match_text.strip()
                        })
    except Exception as e:
        logger.debug(f"Could not read file {path}: {e}")
    return findings

def walk_and_scan(target: str, patterns: List[Tuple[str, Pattern]], ignore_hidden: bool=True) -> List[Dict]:
    """
    Walk a directory (or scan a single file) and return aggregated findings.
    """
    all_findings = []
    if os.path.isfile(target):
        if is_text_file(target):
            logger.info(f"Scanning file: {target}")
            all_findings.extend(scan_file(target, patterns))
        else:
            logger.info(f"Skipping binary file: {target}")
    else:
        for root, dirs, files in os.walk(target):
            if ignore_hidden:
                # Skip hidden dirs like .git
                dirs[:] = [d for d in dirs if not d.startswith('.')]
            for fname in files:
                if ignore_hidden and fname.startswith('.'):
                    continue
                fpath = os.path.join(root, fname)
                if is_text_file(fpath):
                    all_findings.extend(scan_file(fpath, patterns))
    return all_findings

def save_json_report(findings: List[Dict], path: str):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"generated_at": datetime.utcnow().isoformat() + "Z", "findings": findings}, fh, indent=2)
    logger.info(f"Wrote JSON report to {path}")

def save_csv_report(findings: List[Dict], path: str):
    if not findings:
        open(path, "w").close()
        logger.info(f"Wrote empty CSV report to {path}")
        return
    with open(path, "w", newline='', encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["filename", "line", "pattern", "match"])
        writer.writeheader()
        for r in findings:
            writer.writerow(r)
    logger.info(f"Wrote CSV report to {path}")

# ----------------------
# CLI
# ----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Scan files or directories for common hardcoded secrets.")
    p.add_argument("target", help="File or directory to scan")
    p.add_argument("-o", "--output", help="Output report path (default: secrets_report.json)", default="secrets_report.json")
    p.add_argument("--format", choices=["json", "csv"], default="json", help="Report format")
    p.add_argument("--verbose", "-v", action="count", default=0, help="Verbose logging (-v, -vv)")
    p.add_argument("--mask", action="store_true", help="Mask matched secrets in the printed output (keeps report full)")
    p.add_argument("--no-skip-hidden", action="store_true", help="Do NOT skip hidden files/dirs (like .git)")
    return p.parse_args()

def mask_secret(s: str) -> str:
    if len(s) <= 6:
        return "******"
    return s[:3] + "..." + s[-3:]

def main():
    args = parse_args()
    if args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    target = args.target
    if not os.path.exists(target):
        logger.error(f"Target does not exist: {target}")
        return

    findings = walk_and_scan(target, PATTERNS, ignore_hidden=not args.no_skip_hidden)

    # Print summary to stdout
    if not findings:
        logger.warning("No potential secrets found.")
    else:
        logger.info(f"Found {len(findings)} potential secrets:")
        for f in findings:
            display_match = mask_secret(f["match"]) if args.mask else f["match"]
            print(f"{f['filename']}:{f['line']}  [{f['pattern']}]  -> {display_match}")

    # Save report
    out = args.output
    if args.format == "json":
        save_json_report(findings, out)
    else:
        save_csv_report(findings, out)

if __name__ == "__main__":
    main()
