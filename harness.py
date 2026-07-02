#!/usr/bin/env python3
"""
Security testing harness for self-owned websites.

Scope note: run this ONLY against sites you own/control. This script does
non-destructive checks only: HTTP requests to your own endpoints and
publicly-reachable paths. It does not attempt exploitation, brute force,
or automated attack against third parties.

Usage:
    pip install requests
    python harness.py
    (it will ask which URL to test)

    -- or skip the prompt --
    python harness.py --url https://example.com/

Output: a report printed to stdout, and saved to report.json
"""

import argparse
import json
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

TIMEOUT = 10

# --- Security header expectations -----------------------------------------
EXPECTED_HEADERS = {
    "content-security-policy": "Mitigates XSS by restricting script sources. Important here since AI-generated text is rendered.",
    "x-content-type-options": "Should be 'nosniff' to stop MIME sniffing.",
    "x-frame-options": "Should be 'DENY' or 'SAMEORIGIN' to prevent clickjacking (framing your benefit-decision demo).",
    "strict-transport-security": "Enforces HTTPS on repeat visits.",
    "referrer-policy": "Controls how much URL data leaks to other sites via Referer header.",
    "permissions-policy": "Restricts access to browser features (camera, mic, geolocation, etc).",
    "cross-origin-opener-policy": "Isolates browsing context, mitigates some cross-window attacks.",
    "cross-origin-resource-policy": "Controls which origins can embed your resources.",
}

# --- Common paths worth checking on any web app -----------------------------
COMMON_PATHS = [
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    ".env",
    ".env.local",
    ".env.production",
    ".git/config",
    ".git/HEAD",
    "package.json",
    "next.config.js",
    "next.config.mjs",
    "_next/static/chunks/webpack.js",  # existence implies build layout is guessable
    "api/",
    "api/health",
    "api/assess",  # guess based on form purpose - adjust to real routes if known
    "vercel.json",
    ".vercel/project.json",
]

# Paths that, if they return 200 with real content, are meaningful findings
SENSITIVE_PATHS = {".env", ".env.local", ".env.production", ".git/config", ".git/HEAD", "vercel.json", ".vercel/project.json"}


def now():
    return datetime.now(timezone.utc).isoformat()


def check_headers(base_url, results):
    print(f"\n[*] Checking security headers on {base_url}")
    try:
        r = requests.get(base_url, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        results["headers"] = {"error": str(e)}
        print(f"    ERROR: {e}")
        return

    found = {k: v for k, v in r.headers.items()}
    missing = []
    present = {}
    for h, why in EXPECTED_HEADERS.items():
        match = next((v for k, v in found.items() if k.lower() == h), None)
        if match is None:
            missing.append({"header": h, "why_it_matters": why})
        else:
            present[h] = match

    results["headers"] = {
        "status_code": r.status_code,
        "all_response_headers": found,
        "present_security_headers": present,
        "missing_security_headers": missing,
    }

    print(f"    Status: {r.status_code}")
    if missing:
        print(f"    MISSING ({len(missing)}):")
        for m in missing:
            print(f"      - {m['header']}: {m['why_it_matters']}")
    else:
        print("    All checked headers present.")


def check_tls(hostname, results, port=443):
    print(f"\n[*] Checking TLS config for {hostname}:{port}")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                cipher = ssock.cipher()
        not_after = cert.get("notAfter")
        results["tls"] = {
            "protocol_negotiated": version,
            "cipher": cipher,
            "cert_expires": not_after,
            "cert_subject": cert.get("subject"),
        }
        print(f"    Protocol: {version}, Cipher: {cipher[0]}")
        print(f"    Cert expires: {not_after}")
        print("    NOTE: for a full TLS grade (weak ciphers, protocol downgrade,")
        print("    known CVEs), run testssl.sh or Qualys SSL Labs against the host —")
        print("    this check only confirms what your client negotiated, not the")
        print("    full set of what the server will accept.")
    except Exception as e:
        results["tls"] = {"error": str(e)}
        print(f"    ERROR: {e}")


def check_cors(base_url, results):
    print(f"\n[*] Checking CORS behavior on {base_url}")
    test_origin = "https://evil-example-test.invalid"
    try:
        r = requests.get(base_url, headers={"Origin": test_origin}, timeout=TIMEOUT)
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials")
        finding = None
        if acao == "*" and acac and acac.lower() == "true":
            finding = "CRITICAL misconfig: wildcard origin combined with allow-credentials=true is invalid per spec but if a browser/server honors it, any site can read authenticated responses."
        elif acao == test_origin:
            finding = "Server reflects arbitrary Origin back — check whether this is intentional and whether credentials are involved."
        results["cors"] = {
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac,
            "finding": finding,
        }
        print(f"    ACAO: {acao}, ACAC: {acac}")
        if finding:
            print(f"    FINDING: {finding}")
    except requests.RequestException as e:
        results["cors"] = {"error": str(e)}
        print(f"    ERROR: {e}")


def check_common_paths(base_url, results):
    print(f"\n[*] Probing common paths for exposure/misconfig")
    findings = []
    for path in COMMON_PATHS:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
            status = r.status_code
            size = len(r.content)
            entry = {"path": path, "status": status, "size": size}
            if status == 200 and path in SENSITIVE_PATHS and size > 0:
                entry["SEVERITY"] = "HIGH — sensitive file appears to be publicly served"
                print(f"    [HIGH] {path} -> {status} ({size} bytes) — investigate manually")
            elif status == 200:
                print(f"    [info] {path} -> 200 ({size} bytes)")
            else:
                print(f"    [ok]   {path} -> {status}")
            findings.append(entry)
        except requests.RequestException as e:
            findings.append({"path": path, "error": str(e)})
        time.sleep(0.2)  # be gentle, don't hammer your own host
    results["path_probe"] = findings


def check_error_verbosity(base_url, results):
    """Send malformed requests to see if stack traces / internals leak."""
    print(f"\n[*] Checking error-handling verbosity")
    tests = []
    api_guess = urljoin(base_url, "api/assess")
    try:
        r = requests.post(api_guess, json={"malformed": True}, timeout=TIMEOUT)
        leaks_stack = any(kw in r.text.lower() for kw in ["traceback", "at node:", "stack:", "internal server error", "prisma", "env.", "api_key"])
        tests.append({
            "endpoint_guessed": api_guess,
            "status": r.status_code,
            "possible_leak_markers_found": leaks_stack,
            "note": "This guesses a likely API route name; if your real route differs, edit COMMON_PATHS / this function.",
        })
        if leaks_stack:
            print(f"    [WARN] Response body may contain internal details — review manually: {api_guess}")
        else:
            print(f"    [ok] No obvious leak markers on {api_guess} (status {r.status_code})")
    except requests.RequestException as e:
        tests.append({"endpoint_guessed": api_guess, "error": str(e)})
    results["error_verbosity"] = tests


def get_target_url():
    """Ask the user which site to test, either via --url flag or interactively."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=None, help="Site to test, e.g. https://example.com/")
    args = ap.parse_args()

    if args.url:
        raw = args.url
    else:
        raw = input("Which website do you want to test? (e.g. https://example.com/): ").strip()
        while not raw:
            raw = input("Please enter a URL: ").strip()

    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = "https://" + raw  # assume https if they just typed "example.com"

    return raw


def main():
    base_url = get_target_url()
    base_url = base_url if base_url.endswith("/") else base_url + "/"
    hostname = urlparse(base_url).hostname

    print(f"\n[*] Target set to: {base_url}")
    confirm = input("Proceed with scan? This should be a site YOU own/control. (y/n): ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        sys.exit(0)

    results = {"target": base_url, "run_at": now()}

    check_headers(base_url, results)
    check_tls(hostname, results)
    check_cors(base_url, results)
    check_common_paths(base_url, results)
    check_error_verbosity(base_url, results)

    # --- Generate a unique filename ---
    # Extract a clean identifier from the hostname (e.g., "www_dpmc_govt_nz")
    clean_identifier = hostname.replace(".", "_") if hostname else "unknown_target"
    
    # Format the current time for a filename (e.g., "20260702_102523")
    time_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    
    filename = f"report_{clean_identifier}_{time_str}.json"
    
    # Write the report to the unique filename
    with open(filename, "w") as f:
        json.dump(results, f, indent=2, default=str)
        
    print(f"\n[*] Full report written to {filename}")
    print("[*] This harness covers infra/config checks only.")
    print("[*] Run manual_test_cases.md for the XSS / prompt-injection / rate-limit checks")
    print("[*] that need a human to actually submit the form and look at the result.")


if __name__ == "__main__":
    main()
