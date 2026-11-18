#!/usr/bin/env python3
"""
Google Search Console Analytics Monitor for firmarpdfcertificado.com
Features:
  - 100% Zero-dependency Service Account JWT authentication using OpenSSL CLI
  - Pre-flight credentials verification & property permission checking
  - Aggregated Page-level Performance (Impressions, Clicks, CTR, Average Position)
  - Aggregated Query-level Performance (Top search keywords and rank)
  - Page-specific Query Deep-dive (e.g. --page-queries /comprobar-validez...)
  - Device Segmentation (Mobile vs. Desktop vs. Tablet)
  - [Nov 2026 API] Batch Country/Device Filtering via filterLists (--countries esp,mex,col)
  - [Nov 2026 API] Multimodal Search Data (--multimodal: Google Lens / Circle to Search)
  - [Nov 2026 API] Branded Query Classification (--branded: BRANDED vs NON_BRANDED)
Usage:
  python3 scripts/check-gsc-analytics.py [--verify-only]
  python3 scripts/check-gsc-analytics.py [--pages] [--queries] [--days 7]
  python3 scripts/check-gsc-analytics.py --countries esp,mex,col
  python3 scripts/check-gsc-analytics.py --multimodal
  python3 scripts/check-gsc-analytics.py --branded
  python3 scripts/check-gsc-analytics.py --page-queries /firmar-pdf-certificado-mac-iphone/
"""

import os
import sys
import time
import json
import base64
import tempfile
import argparse
import subprocess
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone

DEFAULT_SITE_URL = "sc-domain:firmarpdfcertificado.com"
FALLBACK_SITE_URL = "https://firmarpdfcertificado.com/"
DEFAULT_CREDS_PATH = "/data/data/com.termux/files/home/micro-tools/.gsc_credentials.json"
ALT_CREDS_PATH = "/sdcard/Download/gen-lang-client-0695474766-bd4b18ce3951.json"


def b64url(data: bytes) -> str:
    """Encodes bytes into URL-safe base64 string without trailing '='."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def get_gsc_access_token(creds_path: str) -> tuple[str, str]:
    """
    Acquires a Google OAuth2 Bearer Access Token using Service Account credentials.
    Uses openssl CLI to sign RSA-SHA256 JWT assertion with zero pip dependencies.
    """
    if not os.path.exists(creds_path):
        if os.path.exists(ALT_CREDS_PATH):
            creds_path = ALT_CREDS_PATH
        else:
            return "", f"Credentials file not found at: {creds_path}"

    try:
        with open(creds_path, "r", encoding="utf-8") as f:
            creds = json.load(f)
    except Exception as e:
        return "", f"Failed to parse credentials JSON: {e}"

    client_email = creds.get("client_email", "")
    private_key = creds.get("private_key", "")

    if not client_email or not private_key:
        return "", "Invalid credentials JSON: missing 'client_email' or 'private_key'"

    # 1. Header & Claims
    header = {"alg": "RS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "iss": client_email,
        "scope": "https://www.googleapis.com/auth/webmasters.readonly",
        "aud": "https://oauth2.googleapis.com/token",
        "exp": now + 3600,
        "iat": now
    }

    unsigned_jwt = b64url(json.dumps(header).encode("utf-8")) + "." + b64url(json.dumps(payload).encode("utf-8"))

    # 2. Sign using OpenSSL
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=True) as key_file:
            key_file.write(private_key)
            key_file.flush()
            p = subprocess.Popen(
                ["openssl", "dgst", "-sha256", "-sign", key_file.name],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            sig, err = p.communicate(input=unsigned_jwt.encode("utf-8"))
            if p.returncode != 0:
                return "", f"OpenSSL signature failed: {err.decode('utf-8')}"
    except Exception as e:
        return "", f"Error during JWT signing: {e}"

    signed_jwt = unsigned_jwt + "." + b64url(sig)

    # 3. Exchange JWT for Google Access Token
    token_url = "https://oauth2.googleapis.com/token"
    post_data = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": signed_jwt
    }).encode("utf-8")

    req = urllib.request.Request(
        token_url,
        data=post_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("access_token", ""), client_email
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        return "", f"OAuth2 token exchange failed (HTTP {e.code}): {err_body}"
    except Exception as e:
        return "", f"OAuth2 request failed: {e}"


def list_verified_sites(token: str) -> list[dict]:
    """Retrieves all verified properties accessible to the service account."""
    req = urllib.request.Request(
        "https://www.googleapis.com/webmasters/v3/sites",
        headers={"Authorization": f"Bearer {token}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("siteEntry", [])
    except Exception:
        return []


def query_search_analytics(token: str, site_url: str, body: dict) -> tuple[list[dict], int]:
    """Executes a searchAnalytics.query POST request against the GSC API."""
    encoded_site = urllib.parse.quote(site_url, safe="")
    url = f"https://www.googleapis.com/webmasters/v3/sites/{encoded_site}/searchAnalytics/query"

    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("rows", []), 200
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        try:
            return json.loads(err_msg), e.code
        except Exception:
            return [{"error": err_msg}], e.code
    except Exception as e:
        return [{"error": str(e)}], 0


def format_date_range(days: int) -> tuple[str, str]:
    """
    Computes GSC start and end dates accounting for the standard 2-3 day reporting lag.
    """
    today = datetime.now(timezone.utc).date()
    end_date = today - timedelta(days=2)
    start_date = end_date - timedelta(days=days - 1)
    return start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d")


def verify_gsc_setup(token: str, client_email: str, target_site: str) -> tuple[bool, str]:
    """Verifies that the service account has access to the target Search Console site."""
    print("🔍 [Pre-Flight] Verifying Google Search Console API access...")
    print(f"   Service Account: {client_email}")

    sites = list_verified_sites(token)
    if not sites:
        print("\n❌ No verified Search Console properties found for this Service Account!")
        print("\n💡 ACTION REQUIRED IN GOOGLE SEARCH CONSOLE:")
        print("   1. Open: https://search.google.com/search-console")
        print("   2. Go to: Settings > Users and permissions > Add user")
        print(f"   3. Paste email: {client_email}")
        print("   4. Set Permission: 'Full' (or 'Restricted') > Click Add\n")
        return False, ""

    # Match target site (check domain property or URL prefix)
    matched_site = ""
    for s in sites:
        s_url = s.get("siteUrl", "")
        if "firmarpdfcertificado" in s_url:
            matched_site = s_url
            print(f"✅ GSC Access Confirmed for Property: {s_url}")
            print(f"   Permission Level: {s.get('permissionLevel')}\n")
            return True, matched_site

    print(f"⚠️ Service account has access to other sites ({[s.get('siteUrl') for s in sites]}), but not firmarpdfcertificado.")
    return False, ""


def display_pages_table(rows: list[dict], start_d: str, end_d: str):
    """Renders page-level performance table."""
    print("=========================================================================================")
    print(f"📄 GOOGLE SEARCH CONSOLE — PAGE-LEVEL PERFORMANCE ({start_d} to {end_d})")
    print("=========================================================================================")
    print(f"{'Impressions':>11} | {'Clicks':>6} | {'CTR':>7} | {'Avg Pos':>7} | Page URL")
    print("-" * 89)

    total_impr = sum(r.get("impressions", 0) for r in rows)
    total_clicks = sum(r.get("clicks", 0) for r in rows)

    for r in rows:
        page_url = r.get("keys", [""])[0]
        impr = r.get("impressions", 0)
        clicks = r.get("clicks", 0)
        ctr = (r.get("ctr", 0) * 100)
        pos = r.get("position", 0.0)

        display_url = page_url.replace("https://firmarpdfcertificado.com", "")
        if not display_url:
            display_url = "/ (Homepage)"

        print(f"{impr:11,d} | {clicks:6,d} | {ctr:6.2f}% | {pos:7.1f} | {display_url}")

    print("-" * 89)
    total_ctr = (total_clicks / total_impr * 100) if total_impr else 0.0
    print(f"{total_impr:11,d} | {total_clicks:6,d} | {total_ctr:6.2f}% | {'--':>7} | TOTALS ({len(rows)} Pages)")
    print("=========================================================================================\n")


def display_queries_table(rows: list[dict], start_d: str, end_d: str, limit: int = 25):
    """Renders query-level performance table."""
    print("=========================================================================================")
    print(f"🔍 GOOGLE SEARCH CONSOLE — TOP SEARCH QUERIES ({start_d} to {end_d})")
    print("=========================================================================================")
    print(f"{'Impressions':>11} | {'Clicks':>6} | {'CTR':>7} | {'Avg Pos':>7} | Search Query")
    print("-" * 89)

    for r in rows[:limit]:
        query_text = r.get("keys", [""])[0]
        impr = r.get("impressions", 0)
        clicks = r.get("clicks", 0)
        ctr = (r.get("ctr", 0) * 100)
        pos = r.get("position", 0.0)
        print(f"{impr:11,d} | {clicks:6,d} | {ctr:6.2f}% | {pos:7.1f} | {query_text}")

    remaining = len(rows) - limit
    if remaining > 0:
        print(f"... and {remaining} more long-tail queries (use --limit {len(rows)} to view all)")
    print("=========================================================================================\n")


def display_page_queries(token: str, site_url: str, page_pattern: str, start_d: str, end_d: str, limit: int = 10):
    """Renders top queries for a specific URL."""
    body = {
        "startDate": start_d,
        "endDate": end_d,
        "dimensions": ["query"],
        "dimensionFilterGroups": [
            {
                "filters": [
                    {
                        "dimension": "page",
                        "operator": "contains",
                        "expression": page_pattern
                    }
                ]
            }
        ],
        "rowLimit": 500
    }

    rows, status = query_search_analytics(token, site_url, body)
    print("=========================================================================================")
    print(f"🎯 GSC QUERY BREAKDOWN FOR: {page_pattern} ({start_d} to {end_d})")
    print("=========================================================================================")
    if status != 200 or not isinstance(rows, list) or not rows:
        print(f"No query records found matching '{page_pattern}' in this date range.")
        print("=========================================================================================\n")
        return

    # Sort by impressions descending
    sorted_rows = sorted(rows, key=lambda x: x.get("impressions", 0), reverse=True)

    print(f"{'Impressions':>11} | {'Clicks':>6} | {'CTR':>7} | {'Avg Pos':>7} | Query")
    print("-" * 89)
    for r in sorted_rows[:limit]:
        q = r.get("keys", [""])[0]
        impr = r.get("impressions", 0)
        clicks = r.get("clicks", 0)
        ctr = (r.get("ctr", 0) * 100)
        pos = r.get("position", 0.0)
        print(f"{impr:11,d} | {clicks:6,d} | {ctr:6.2f}% | {pos:7.1f} | {q}")
    print("=========================================================================================\n")


def display_devices(token: str, site_url: str, start_d: str, end_d: str):
    """Renders device segmentation breakdown."""
    body = {
        "startDate": start_d,
        "endDate": end_d,
        "dimensions": ["device"],
        "rowLimit": 10
    }
    rows, status = query_search_analytics(token, site_url, body)
    if status != 200 or not rows:
        return

    print("=========================================================================================")
    print(f"📱 GOOGLE SEARCH CONSOLE — DEVICE BREAKDOWN ({start_d} to {end_d})")
    print("=========================================================================================")
    print(f"{'Device':<12} | {'Impressions':>12} | {'Clicks':>8} | {'CTR':>8} | {'Avg Pos':>8}")
    print("-" * 60)
    for r in rows:
        dev = r.get("keys", [""])[0]
        impr = r.get("impressions", 0)
        clicks = r.get("clicks", 0)
        ctr = (r.get("ctr", 0) * 100)
        pos = r.get("position", 0.0)
        print(f"{dev:<12} | {impr:12,d} | {clicks:8,d} | {ctr:7.2f}% | {pos:8.1f}")
    print("=========================================================================================\n")


def display_countries_table(rows: list[dict], start_d: str, end_d: str, filter_codes: list[str] = None):
    """Renders country breakdown table (supports Nov 2026 filterLists batch filtering)."""
    filter_label = f" [Filtered: {', '.join(filter_codes).upper()}]" if filter_codes else ""
    print("=========================================================================================")
    print(f"🌍 GOOGLE SEARCH CONSOLE — COUNTRY BREAKDOWN{filter_label} ({start_d} to {end_d})")
    print("=========================================================================================")
    print(f"{'Country':<10} | {'Impressions':>11} | {'Clicks':>6} | {'CTR':>7} | {'Avg Pos':>7}")
    print("-" * 55)

    total_impr = sum(r.get("impressions", 0) for r in rows)
    total_clicks = sum(r.get("clicks", 0) for r in rows)

    for r in rows:
        c_code = r.get("keys", [""])[0].upper()
        impr = r.get("impressions", 0)
        clicks = r.get("clicks", 0)
        ctr = (r.get("ctr", 0) * 100)
        pos = r.get("position", 0.0)
        print(f"{c_code:<10} | {impr:11,d} | {clicks:6,d} | {ctr:6.2f}% | {pos:7.1f}")

    print("-" * 55)
    total_ctr = (total_clicks / total_impr * 100) if total_impr else 0.0
    print(f"{'TOTALS':<10} | {total_impr:11,d} | {total_clicks:6,d} | {total_ctr:6.2f}% | {'--':>7}")
    print("=========================================================================================\n")


def display_multimodal(token: str, site_url: str, start_d: str, end_d: str, filter_groups: list = None):
    """Queries and renders webMultimodal (Google Lens, Circle to Search, visual uploads) metrics."""
    body = {
        "startDate": start_d,
        "endDate": end_d,
        "type": "webMultimodal",
        "rowLimit": 50
    }
    if filter_groups:
        body["dimensionFilterGroups"] = filter_groups

    rows, status = query_search_analytics(token, site_url, body)
    print("=========================================================================================")
    print(f"📷 GOOGLE SEARCH CONSOLE — MULTIMODAL SEARCH (Lens & Circle to Search) ({start_d} to {end_d})")
    print("=========================================================================================")
    if status != 200 or not rows:
        print("ℹ️ No multimodal search data returned for this period.")
        print("   (Captures visual discoveries from Google Lens, Circle to Search, and image uploads)")
        print("=========================================================================================\n")
        return

    first = rows[0]
    impr = first.get("impressions", 0)
    clicks = first.get("clicks", 0)
    ctr = (first.get("ctr", 0) * 100)
    pos = first.get("position", 0.0)

    print(f"{'Impressions':>11} | {'Clicks':>6} | {'CTR':>7} | {'Avg Pos':>7} | Scope")
    print("-" * 65)
    print(f"{impr:11,d} | {clicks:6,d} | {ctr:6.2f}% | {pos:7.1f} | Visual Search Aggregate")
    print("-" * 65)
    print("💡 Multimodal search captures impressions from Android Circle to Search,")
    print("   Google Lens camera snaps, and direct visual search uploads.")
    print("=========================================================================================\n")


def display_branded(token: str, site_url: str, start_d: str, end_d: str, filter_groups: list = None):
    """Queries brandedClassification (BRANDED vs NON_BRANDED) introduced in Nov 2026."""
    body = {
        "startDate": start_d,
        "endDate": end_d,
        "dimensions": ["brandedClassification"],
        "rowLimit": 10
    }
    if filter_groups:
        body["dimensionFilterGroups"] = filter_groups

    rows, status = query_search_analytics(token, site_url, body)
    print("=========================================================================================")
    print(f"🏷️ GOOGLE SEARCH CONSOLE — BRANDED QUERY CLASSIFICATION ({start_d} to {end_d})")
    print("=========================================================================================")
    if status != 200 or not rows:
        print("ℹ️ No branded classification data returned (empty rows).")
        print("   Note: Google restricts 'brandedClassification' to top-level properties with")
        print("   sufficient search query/impression thresholds. Smaller micro-SaaS properties")
        print("   are classified almost 100% as non-branded organic utility traffic.")
        print("=========================================================================================\n")
        return

    print(f"{'Classification':<18} | {'Impressions':>11} | {'Clicks':>6} | {'CTR':>7} | {'Avg Pos':>7}")
    print("-" * 60)
    for r in rows:
        label = r.get("keys", [""])[0]
        impr = r.get("impressions", 0)
        clicks = r.get("clicks", 0)
        ctr = (r.get("ctr", 0) * 100)
        pos = r.get("position", 0.0)
        print(f"{label:<18} | {impr:11,d} | {clicks:6,d} | {ctr:6.2f}% | {pos:7.1f}")
    print("=========================================================================================\n")


def main():
    parser = argparse.ArgumentParser(description="Google Search Console Analytics Monitor")
    parser.add_argument("--creds", type=str, default=DEFAULT_CREDS_PATH, help="Path to Service Account JSON key")
    parser.add_argument("--site", type=str, default=DEFAULT_SITE_URL, help="Target GSC Site Property URL")
    parser.add_argument("--days", type=int, default=7, help="Date range duration in days (default: 7)")
    parser.add_argument("--pages", action="store_true", help="Display page-level metrics")
    parser.add_argument("--queries", action="store_true", help="Display top search queries")
    parser.add_argument("--page-queries", type=str, default=None, help="Display top queries for a specific URL/path")
    parser.add_argument("--devices", action="store_true", help="Display device segmentation")
    parser.add_argument("--limit", type=int, default=25, help="Number of queries to display")
    parser.add_argument("--verify-only", action="store_true", help="Verify credentials and property access only")

    # New Nov 2026 API Flags
    parser.add_argument("--countries", type=str, default=None, help="Filter by comma-separated country codes e.g. esp,mex,col (Nov 2026 filterLists)")
    parser.add_argument("--multimodal", action="store_true", help="Display visual search metrics (Google Lens & Circle to Search)")
    parser.add_argument("--branded", action="store_true", help="Display Branded vs. Non-Branded search classification")
    parser.add_argument("--filter-devices", type=str, default=None, help="Filter by comma-separated device types e.g. DESKTOP,MOBILE (Nov 2026 filterLists)")

    args = parser.parse_args()

    # 1. Acquire Access Token
    token, err_or_email = get_gsc_access_token(args.creds)
    if not token:
        print(f"❌ Authentication Failed: {err_or_email}")
        sys.exit(1)

    client_email = err_or_email

    # 2. Pre-flight site verification
    ok, verified_site = verify_gsc_setup(token, client_email, args.site)
    if not ok:
        sys.exit(1)

    site_url = verified_site or args.site

    if args.verify_only:
        sys.exit(0)

    start_d, end_d = format_date_range(args.days)

    # 3. Construct Nov 2026 filterLists
    filter_lists = []
    c_list = None
    if args.countries:
        c_list = [c.strip().lower() for c in args.countries.split(",") if c.strip()]
        if c_list:
            filter_lists.append({
                "dimension": "country",
                "operator": "including",
                "expressions": c_list
            })
    if args.filter_devices:
        d_list = [d.strip().upper() for d in args.filter_devices.split(",") if d.strip()]
        if d_list:
            filter_lists.append({
                "dimension": "device",
                "operator": "including",
                "expressions": d_list
            })

    dimension_filter_groups = [{"filterLists": filter_lists}] if filter_lists else None

    # 4. Multimodal & Branded reporting
    if args.multimodal:
        display_multimodal(token, site_url, start_d, end_d, dimension_filter_groups)

    if args.branded:
        display_branded(token, site_url, start_d, end_d, dimension_filter_groups)

    # 5. Page-specific deep dive
    if args.page_queries:
        display_page_queries(token, site_url, args.page_queries, start_d, end_d, limit=args.limit)
        return

    # 6. Standard reporting
    is_targeted_view = args.pages or args.queries or args.devices or args.multimodal or args.branded
    show_all = not is_targeted_view and not args.countries

    # If --countries passed without --pages/--queries, show Country Breakdown
    if args.countries and not (args.pages or args.queries):
        body = {
            "startDate": start_d,
            "endDate": end_d,
            "dimensions": ["country"],
            "dimensionFilterGroups": dimension_filter_groups,
            "rowLimit": 50
        }
        rows, status = query_search_analytics(token, site_url, body)
        if status == 200 and isinstance(rows, list):
            display_countries_table(rows, start_d, end_d, filter_codes=c_list)

    if show_all or args.pages:
        body = {
            "startDate": start_d,
            "endDate": end_d,
            "dimensions": ["page"],
            "rowLimit": 100
        }
        if dimension_filter_groups:
            body["dimensionFilterGroups"] = dimension_filter_groups
        rows, status = query_search_analytics(token, site_url, body)
        if status == 200 and isinstance(rows, list):
            display_pages_table(rows, start_d, end_d)

    if show_all or args.queries:
        body = {
            "startDate": start_d,
            "endDate": end_d,
            "dimensions": ["query"],
            "rowLimit": args.limit
        }
        if dimension_filter_groups:
            body["dimensionFilterGroups"] = dimension_filter_groups
        rows, status = query_search_analytics(token, site_url, body)
        if status == 200 and isinstance(rows, list):
            display_queries_table(rows, start_d, end_d, limit=args.limit)

    if show_all or args.devices:
        display_devices(token, site_url, start_d, end_d)


if __name__ == "__main__":
    main()
