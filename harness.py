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

try:
    import requests
except ImportError:
    print("[!] 'requests' library is missing.")
    print("    Auto-install has been disabled deliberately: when you suspect a host")
    print("    is compromised, this environment shouldn't be silently pulling and")
    print("    executing code from the network on your behalf.")
    print("    Install it yourself first:  pip install requests")
    sys.exit(1)

TIMEOUT = 10

# --- Safety limits (relevant when scanning a possibly-compromised host) ----
MAX_RESPONSE_BYTES = 5 * 1024 * 1024   # 5 MB cap; refuse to buffer more
MAX_REDIRECTS = 3
CONNECT_TIMEOUT = 6
READ_TIMEOUT = 10
REQUEST_TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)


def strip_terminal_escapes(text):
    """
    Remove ANSI/terminal escape sequences before printing anything that came
    from a remote response. A malicious/compromised server could otherwise
    inject escape codes to manipulate your terminal.
    """
    import re
    if not isinstance(text, str):
        return text
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text


def safe_get(url, **kwargs):
    """
    Wrapper around requests.get that:
      - never follows redirects automatically (so hops can be inspected/validated)
      - caps how much of the body is ever buffered into memory
      - uses separate connect/read timeouts
    """
    kwargs.pop("allow_redirects", None)
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    kwargs["allow_redirects"] = False
    kwargs["stream"] = True
    r = requests.get(url, **kwargs)
    content = b""
    for chunk in r.iter_content(chunk_size=8192):
        content += chunk
        if len(content) > MAX_RESPONSE_BYTES:
            r.close()
            raise ValueError(f"Response exceeded {MAX_RESPONSE_BYTES} byte safety cap "
                              f"while fetching {url} — aborted before fully buffering.")
    r._content = content  # let existing code keep using r.text / r.content
    return r


def follow_redirects_in_scope(base_url, url, max_hops=MAX_REDIRECTS, results=None, chain_key="redirect_chain"):
    """
    Manually follow redirects with a hop cap, flagging any hop that leaves the
    original domain — a common sign of a compromised host quietly redirecting
    visitors elsewhere (malvertising, phishing kits, etc).

    chain_key lets separate scan passes (e.g. HTTPS vs HTTP downgrade) record
    their redirect chains under distinct result keys instead of clobbering
    each other.
    """
    original_host = urlparse(base_url).hostname
    current = url
    hops = []
    r = None
    for _ in range(max_hops + 1):
        r = safe_get(current)
        hop = {"url": current, "status": r.status_code}
        hops.append(hop)
        if r.status_code in (301, 302, 303, 307, 308) and "Location" in r.headers:
            nxt = urljoin(current, r.headers["Location"])
            nxt_host = urlparse(nxt).hostname
            if nxt_host != original_host:
                hop["FLAG"] = f"Redirects OFF-DOMAIN to {nxt_host} — verify this is intentional."
                print(f"    [FLAG] Redirect leaves original domain: {current} -> {nxt}")
            current = nxt
            continue
        break
    else:
        hops.append({"note": f"Stopped after {max_hops} redirects (possible loop or off-scope chain)."})
    if results is not None:
        results.setdefault(chain_key, []).extend(hops)
    return r

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


def _parse_set_cookie(raw_cookie):
    """
    Parse a single raw Set-Cookie header string into name + flags.
    Doesn't use http.cookiejar because it normalizes away the exact
    HttpOnly/SameSite casing/values we want to report on.
    """
    parts = [p.strip() for p in raw_cookie.split(";")]
    name = parts[0].split("=", 1)[0] if parts else "(unknown)"
    attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else True)
              for p in parts[1:]}
    return {
        "name": name,
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": attrs.get("samesite"),
        "raw": raw_cookie,
    }


def check_cookies(base_url, results):
    """
    Inspect Set-Cookie headers for the Secure, HttpOnly, and SameSite flags.

    Why this matters:
      - Missing HttpOnly: client-side JS (including any injected via XSS) can
        read the cookie and exfiltrate it — turns a minor XSS into full
        session theft.
      - Missing Secure: the cookie can be sent over plain HTTP, exposing it
        to network-level interception.
      - Missing/weak SameSite: opens the door to CSRF; SameSite=None without
        Secure is invalid and rejected by modern browsers anyway, but is
        still worth flagging as a misconfiguration.
    """
    print(f"\n[*] Checking cookie flags on {base_url}")
    try:
        r = safe_get(base_url)
    except (requests.RequestException, ValueError) as e:
        results["cookies"] = {"error": str(e)}
        print(f"    ERROR: {e}")
        return

    # requests merges multiple Set-Cookie headers into one comma-joined
    # string on r.headers, which breaks parsing (cookie values/Expires can
    # contain commas). Pull the raw, unmerged list instead when available.
    raw_cookies = []
    try:
        raw_cookies = list(r.raw.headers.getlist("Set-Cookie"))
    except AttributeError:
        single = r.headers.get("Set-Cookie")
        if single:
            raw_cookies = [single]

    if not raw_cookies:
        results["cookies"] = {"count": 0, "note": "No Set-Cookie headers observed on this response."}
        print("    No cookies set on this response (may still be set elsewhere, e.g. after login).")
        return

    findings = []
    for raw in raw_cookies:
        parsed = _parse_set_cookie(raw)
        issues = []
        if not parsed["secure"]:
            issues.append("missing Secure — cookie can be sent over plain HTTP")
        if not parsed["httponly"]:
            issues.append("missing HttpOnly — readable by JavaScript, including injected XSS")
        samesite = (parsed["samesite"] or "").lower()
        if not samesite:
            issues.append("missing SameSite — defaults vary by browser, don't rely on it")
        elif samesite == "none" and not parsed["secure"]:
            issues.append("SameSite=None without Secure — invalid combination, browsers will reject this cookie")
        parsed["issues"] = issues
        findings.append(parsed)

        label = "HIGH" if issues else "ok"
        print(f"    [{label}] {parsed['name']}: Secure={parsed['secure']} "
              f"HttpOnly={parsed['httponly']} SameSite={parsed['samesite']}")
        for issue in issues:
            print(f"           - {issue}")

    results["cookies"] = {"count": len(findings), "cookies": findings}


def check_http_downgrade(hostname, https_results, results):
    """
    Explicitly probe the plain-HTTP version of the site and verify it does
    nothing but redirect cleanly to HTTPS.

    This is a distinct check from the main HTTPS scan, run second and on
    purpose — not because HTTP is untrusted by default, but because:
      - If HTTP serves real content (200, non-empty body) instead of
        redirecting, that content is being sent unencrypted and is
        trivially interceptable/modifiable in transit (classic MITM target).
      - If HTTP's final content differs from the HTTPS page's content, that's
        a strong signal something is injecting/serving different content
        depending on scheme — worth investigating as a possible compromise,
        not just a config oversight.
      - If HTTP redirects off-domain, follow_redirects_in_scope already
        flags that.
    """
    http_url = f"http://{hostname}/"
    print(f"\n[*] Checking HTTP -> HTTPS downgrade behavior on {http_url}")
    try:
        r = follow_redirects_in_scope(http_url, http_url, results=results, chain_key="redirect_chain_http")
    except (requests.RequestException, ValueError) as e:
        results["http_downgrade"] = {"error": str(e)}
        print(f"    ERROR: {e}")
        return

    chain = results.get("redirect_chain_http", [])
    first_hop = chain[0] if chain else {}
    first_hop_status = first_hop.get("status")
    final_scheme = urlparse(r.url if hasattr(r, "url") else http_url).scheme
    ended_on_https = final_scheme == "https" or any(
        urlparse(hop.get("url", "")).scheme == "https" for hop in chain[1:]
    )

    entry = {
        "first_hop_status": first_hop_status,
        "final_status": r.status_code,
        # Plaintext exposure means the very first plain-HTTP request itself
        # returned 200 (served content directly) instead of redirecting.
        "served_over_plaintext": first_hop_status == 200,
    }

    if entry["served_over_plaintext"]:
        entry["SEVERITY"] = "HIGH — HTTP serves real content instead of redirecting to HTTPS"
        print("    [HIGH] Plain HTTP returned a real 200 response instead of redirecting.")
        print("           Content sent this way is unencrypted and interceptable/modifiable in transit.")
    elif not ended_on_https and r.status_code not in (301, 302, 303, 307, 308):
        entry["note"] = "HTTP did not redirect and did not return a normal 200 either — investigate manually."
        print(f"    [WARN] Unexpected status from plain HTTP: {r.status_code}")
    else:
        # Compare against the HTTPS homepage content, if we have it, to catch
        # divergent content served depending on scheme.
        https_body = https_results.get("_homepage_body")
        if https_body is not None and r.content:
            if r.content != https_body and len(r.content) > 0:
                entry["content_diverges_from_https"] = True
                entry["SEVERITY"] = "MEDIUM — HTTP body differs from HTTPS body before redirect completes"
                print("    [WARN] Content served on the initial HTTP hop differs from the HTTPS page.")
            else:
                entry["content_diverges_from_https"] = False
        print(f"    [ok] HTTP redirects to HTTPS as expected (final status {r.status_code}).")

    results["http_downgrade"] = entry


def check_headers(base_url, results):
    print(f"\n[*] Checking security headers on {base_url}")
    try:
        r = follow_redirects_in_scope(base_url, base_url, results=results, chain_key="redirect_chain_https")
    except (requests.RequestException, ValueError) as e:
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
    results["_homepage_body"] = r.content  # stashed for HTTP-vs-HTTPS content comparison

    print(f"    Status: {r.status_code}")
    if missing:
        print(f"    MISSING ({len(missing)}):")
        for m in missing:
            print(f"      - {m['header']}: {m['why_it_matters']}")
    else:
        print("    All checked headers present.")


def check_dns(hostname, results):
    """
    Log the currently-resolved IP(s) for the target. Useful as a tamper-evident
    record: if you're worried about compromise (e.g. DNS hijacking, a rogue
    A/CNAME record pointing traffic elsewhere), comparing this across scans
    or against your DNS provider's dashboard is a cheap sanity check.
    """
    print(f"\n[*] Resolving DNS for {hostname}")
    try:
        infos = socket.getaddrinfo(hostname, 443)
        ips = sorted(set(info[4][0] for info in infos))
        results["dns"] = {"hostname": hostname, "resolved_ips": ips}
        print(f"    Resolved IP(s): {', '.join(ips)}")
        print("    Cross-check these against your host/registrar/DNS provider's")
        print("    dashboard if you suspect DNS hijacking.")
    except socket.gaierror as e:
        results["dns"] = {"error": str(e)}
        print(f"    ERROR: {e}")


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
        r = safe_get(base_url, headers={"Origin": test_origin})
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
    except (requests.RequestException, ValueError) as e:
        results["cors"] = {"error": str(e)}
        print(f"    ERROR: {e}")


def check_common_paths(base_url, results):
    print(f"\n[*] Probing common paths for exposure/misconfig")
    findings = []
    for path in COMMON_PATHS:
        url = urljoin(base_url, path)
        try:
            r = safe_get(url)
            status = r.status_code
            size = len(r.content)
            entry = {"path": path, "status": status, "size": size}
            if status == 200 and path in SENSITIVE_PATHS and size > 0:
                entry["SEVERITY"] = "HIGH — sensitive file appears to be publicly served"
                print(f"    [HIGH] {path} -> {status} ({size} bytes) — investigate manually")
                print("           Do NOT open this file in a browser. View it as plain text only")
                print("           (e.g. `less` / a text editor) — never execute or import it.")
            elif status == 200:
                print(f"    [info] {path} -> 200 ({size} bytes)")
            else:
                print(f"    [ok]   {path} -> {status}")
            findings.append(entry)
        except (requests.RequestException, ValueError) as e:
            findings.append({"path": path, "error": strip_terminal_escapes(str(e))})
        time.sleep(0.2)  # be gentle, don't hammer your own host
    results["path_probe"] = findings


def check_error_verbosity(base_url, results):
    """Send malformed requests to see if stack traces / internals leak."""
    print(f"\n[*] Checking error-handling verbosity")
    tests = []
    api_guess = urljoin(base_url, "api/assess")
    try:
        r = requests.post(
            api_guess,
            json={"malformed": True},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,  # don't silently POST to wherever a redirect points
        )
        # Cap how much of the body we scan/store, same rationale as safe_get.
        body = r.text[:MAX_RESPONSE_BYTES]
        leaks_stack = any(kw in body.lower() for kw in ["traceback", "at node:", "stack:", "internal server error", "prisma", "env.", "api_key"])
        tests.append({
            "endpoint_guessed": api_guess,
            "status": r.status_code,
            "possible_leak_markers_found": leaks_stack,
            "note": "This guesses a likely API route name; if your real route differs, edit COMMON_PATHS / this function.",
        })
        if leaks_stack:
            print(f"    [WARN] Response body may contain internal details — review manually: {api_guess}")
            print("           Review the saved JSON report in a text editor, not a browser.")
        else:
            print(f"    [ok] No obvious leak markers on {api_guess} (status {r.status_code})")
    except requests.RequestException as e:
        tests.append({"endpoint_guessed": api_guess, "error": strip_terminal_escapes(str(e))})
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
    try:
        raw_url = get_target_url()
        hostname = urlparse(raw_url if "://" in raw_url else "https://" + raw_url).hostname
        if not hostname:
            print(f"[CRITICAL ERROR] Could not parse a hostname out of: {raw_url}")
            return

        # Always run the deep scan against HTTPS, regardless of what scheme the
        # user typed — HTTPS is the canonical, trusted-transport version of the
        # site and is what path/cookie/CORS findings should reflect. Plain HTTP
        # is checked afterward, deliberately, as a narrower downgrade check.
        https_url = f"https://{hostname}/"

        print(f"\n[*] Canonical HTTPS target: {https_url}")
        print(f"[*] Will also check plain-HTTP downgrade behavior for: http://{hostname}/")
        confirm = input("Proceed with scan? This should be a site YOU own/control. (y/n): ").strip().lower()

        if confirm != "y":
            print("Aborted.")
            return

        results = {"target": https_url, "run_at": now()}

        # --- Pass 1: HTTPS (canonical, deep scan) ---
        check_dns(hostname, results)
        check_headers(https_url, results)
        check_cookies(https_url, results)
        check_tls(hostname, results)
        check_cors(https_url, results)
        check_common_paths(https_url, results)
        check_error_verbosity(https_url, results)

        # --- Pass 2: HTTP (downgrade / plaintext-exposure check only) ---
        check_http_downgrade(hostname, results, results)

        # Strip internal-only scratch data before writing the report.
        results.pop("_homepage_body", None)

        # --- Generate a unique filename ---
        clean_identifier = hostname.replace(".", "_") if hostname else "unknown_target"
        time_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"report_{clean_identifier}_{time_str}.json"
        
        # FIX: Force the file to save in the script's actual folder
        import os
        script_dir = sys.path[0] if sys.path[0] else os.getcwd()
        full_path = os.path.join(script_dir, filename)

        with open(full_path, "w") as f:
            json.dump(results, f, indent=2, default=str)

        print(f"\n[*] Full report written to: {full_path}")
        print("[*] This harness covers infra/config checks only.")
        print("[*] Run manual_test_cases.md for the XSS / prompt-injection / rate-limit checks")
        print("[*] that need a human to actually submit the form and look at the result.")

    except Exception as e:
        print(f"\n[CRITICAL ERROR] The script crashed: {e}")
        
    finally:
        # This forces the PowerShell/CMD window to stay open no matter what
        print("\n" + "="*40)
        input("Process finished. Press ENTER to close this window...")


if __name__ == "__main__":
    main()
