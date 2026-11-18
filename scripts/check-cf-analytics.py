#!/usr/bin/env python3
"""
Cloudflare Edge & Traffic Analytics Monitor for firmarpdfcertificado.com
Features:
  - Pre-flight credential verification (verifies rotated keys/tokens before running GraphQL)
  - Daily request volume time-series (real-time edge traffic)
  - HTTP status code distribution (200, 301, 404, 504)
  - Clean Top Content URLs (filters out CSS/JS/images)
  - Top 404 bot scanner probe targets
  - AI crawler tracking (GPTBot, bingbot, Googlebot)
  - Domestic Spain (ES) traffic & Top Countries breakdown
Usage:
  python3 scripts/check-cf-analytics.py [--days 7] [--verify-only]
  CLOUDFLARE_API_KEY="xxx" python3 scripts/check-cf-analytics.py
"""

import os
import sys
import json
import argparse
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

DEFAULT_ZONE_ID = "9ae01356cb36f15cd5f0135f6acc4af1"  # firmarpdfcertificado.com
CF_CREDS_FILE = "/data/data/com.termux/files/home/micro-tools/.cloudflare_credentials.json"

def load_cf_creds():
    email = os.environ.get("CLOUDFLARE_EMAIL", "")
    key = os.environ.get("CLOUDFLARE_API_KEY", "")
    if os.path.exists(CF_CREDS_FILE):
        try:
            with open(CF_CREDS_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                email = email or d.get("email", "")
                key = key or d.get("api_key", "")
        except Exception:
            pass
    return email, key

DEFAULT_EMAIL, DEFAULT_KEY = load_cf_creds()
USER_AGENT = "CFAnalytics/1.0"


def make_request(url, headers, payload=None, timeout=15):
    """Executes an HTTP request using urllib with custom User-Agent to avoid Cloudflare WAF drops."""
    data = json.dumps(payload).encode("utf-8") if payload else None
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")), resp.status
    except urllib.error.HTTPError as e:
        try:
            err_json = json.loads(e.read().decode("utf-8"))
            return err_json, e.code
        except Exception:
            return {"error": str(e)}, e.code
    except Exception as e:
        return {"error": str(e)}, 0


def verify_credentials(email, key, token=None):
    """
    Pre-flight verification function:
    Verifies that the provided API key or API token is active and valid before running queries.
    Handles rotated keys gracefully.
    """
    print("🔍 [Pre-Flight] Verifying Cloudflare credentials...")

    # Case 1: Bearer Token provided
    if token:
        headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json"
        }
        res, status = make_request("https://api.cloudflare.com/client/v4/user/tokens/verify", headers)
        if status == 200 and res.get("success"):
            print("✅ Cloudflare API Token verified successfully!")
            return headers, "token"
        else:
            print(f"❌ Cloudflare API Token verification FAILED (HTTP {status}): {res.get('errors')}")
            return None, None

    # Case 2: Global API Key + Email
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": key,
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json"
    }
    res, status = make_request("https://api.cloudflare.com/client/v4/user", headers)
    if status == 200 and res.get("success"):
        user_email = res.get("result", {}).get("email", email)
        user_id = res.get("result", {}).get("id", "unknown")
        print(f"✅ Cloudflare API Key verified! Authenticated as: {user_email} (User ID: {user_id[:8]}...)")
        return headers, "key"
    else:
        errs = res.get("errors", [{"message": "Unknown authentication failure"}])
        print(f"\n❌ Cloudflare Pre-Flight Verification FAILED (HTTP {status})!")
        print(f"   Error details: {errs}")
        print("\n💡 The API Key may have been rotated. To supply a new key, run:")
        print("   export CLOUDFLARE_API_KEY='your_new_key'")
        print("   export CLOUDFLARE_EMAIL='ajay2026kr@gmail.com'")
        print("   python3 scripts/check-cf-analytics.py\n")
        return None, None


def fetch_zone_analytics(headers, zone_id, days=7, all_paths=False):
    """Queries Cloudflare GraphQL API for traffic, status codes, top paths, and geography."""
    end_dt = datetime.now(timezone.utc)
    since_dt = end_dt - timedelta(days=days)
    since = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    until = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    q = """
    query GetCFAnalytics($zoneTag: String!, $since: String!, $until: String!) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          daily: httpRequestsAdaptiveGroups(
            limit: 30
            filter: { datetime_geq: $since, datetime_leq: $until }
            orderBy: [count_DESC]
          ) {
            count
            dimensions { date }
          }
          statusCodes: httpRequestsAdaptiveGroups(
            limit: 8
            filter: { datetime_geq: $since, datetime_leq: $until }
            orderBy: [count_DESC]
          ) {
            count
            dimensions { edgeResponseStatus }
          }
          top200Paths: httpRequestsAdaptiveGroups(
            limit: 30
            filter: { datetime_geq: $since, datetime_leq: $until, edgeResponseStatus: 200 }
            orderBy: [count_DESC]
          ) {
            count
            dimensions { clientRequestPath }
          }
          top404Paths: httpRequestsAdaptiveGroups(
            limit: 10
            filter: { datetime_geq: $since, datetime_leq: $until, edgeResponseStatus: 404 }
            orderBy: [count_DESC]
          ) {
            count
            dimensions { clientRequestPath }
          }
          topUserAgents: httpRequestsAdaptiveGroups(
            limit: 12
            filter: { datetime_geq: $since, datetime_leq: $until, edgeResponseStatus: 200 }
            orderBy: [count_DESC]
          ) {
            count
            dimensions { userAgent }
          }
          topCountries: httpRequestsAdaptiveGroups(
            limit: 15
            filter: { datetime_geq: $since, datetime_leq: $until }
            orderBy: [count_DESC]
          ) {
            count
            dimensions { clientCountryName }
          }
          spainPaths: httpRequestsAdaptiveGroups(
            limit: 10
            filter: { datetime_geq: $since, datetime_leq: $until, clientCountryName: "ES", edgeResponseStatus: 200 }
            orderBy: [count_DESC]
          ) {
            count
            dimensions { clientRequestPath }
          }
        }
      }
    }
    """

    payload = {
        "query": q,
        "variables": {"zoneTag": zone_id, "since": since, "until": until}
    }

    res, status = make_request("https://api.cloudflare.com/client/v4/graphql", headers, payload, timeout=20)
    if status != 200 or not res.get("data"):
        print(f"❌ GraphQL Query Failed: {res.get('errors')}")
        return

    zone_data = res["data"]["viewer"]["zones"][0]

    # 1. Total & Status Code Distribution
    status_list = zone_data.get("statusCodes", [])
    total_requests = sum(s["count"] for s in status_list)

    print(f"\n========================================================")
    print(f"📊 CLOUDFLARE EDGE ANALYTICS — PAST {days} DAYS")
    print(f"========================================================")
    print(f"Total Edge Requests: {total_requests:,}")
    print("\n--- HTTP Status Code Breakdown ---")
    for s in status_list:
        cnt = s["count"]
        pct = (cnt / total_requests * 100) if total_requests else 0
        st = s["dimensions"]["edgeResponseStatus"]
        label = "Clean Hits" if st == 200 else ("Redirects" if st in (301, 302) else ("Bot Scanners" if st == 404 else "Other"))
        print(f"  HTTP {st}: {cnt:6,} ({pct:5.1f}%) [{label}]")

    # 2. Daily Traffic Volume (Chronological)
    daily_list = sorted(zone_data.get("daily", []), key=lambda x: x["dimensions"]["date"])
    print(f"\n--- Daily Edge Traffic Timeline ---")
    for d in daily_list:
        date_str = d["dimensions"]["date"]
        cnt = d["count"]
        bar = "█" * max(1, int(cnt / max(1, max(x["count"] for x in daily_list)) * 25))
        print(f"  {date_str}: {cnt:5,} reqs {bar}")

    # 3. Top Content Pages (Cleaned)
    paths_list = zone_data.get("top200Paths", [])
    ignored_exts = (".js", ".css", ".png", ".jpg", ".svg", ".ico", ".webmanifest", "robots.txt")
    print(f"\n--- Top Content Pages (HTTP 200 OK) ---")
    rank = 1
    for p in paths_list:
        path = p["dimensions"]["clientRequestPath"]
        if not all_paths and any(path.endswith(ext) or path.startswith("/_astro/") for ext in ignored_exts):
            continue
        print(f"  #{rank:02d}: {p['count']:5,} reqs -> {path}")
        rank += 1
        if rank > 12:
            break

    # 4. Top 404 Bot Scanners
    p404_list = zone_data.get("top404Paths", [])
    if p404_list:
        print(f"\n--- Top 404 Probe Targets (Automated Scanners) ---")
        for p in p404_list[:6]:
            print(f"  {p['count']:4,} hits -> {p['dimensions']['clientRequestPath']}")

    # 5. AI Crawlers vs. Real Browsers
    ua_list = zone_data.get("topUserAgents", [])
    print(f"\n--- Top User-Agents (AI Crawlers & Browsers) ---")
    for u in ua_list[:8]:
        ua = u["dimensions"]["userAgent"]
        tag = "🤖 [AI Crawler]" if any(bot in ua for bot in ("GPTBot", "bingbot", "Googlebot", "ClaudeBot", "PerplexityBot")) else "👤 [Browser]"
        print(f"  {u['count']:4,} reqs {tag} -> {ua[:75]}")

    # 6. Top Countries & Spain (ES) Activity
    countries_list = zone_data.get("topCountries", [])
    print(f"\n--- Top Countries by Traffic ---")
    sp_count = 0
    for c in countries_list[:8]:
        cname = c["dimensions"]["clientCountryName"] or "Unknown"
        cnt = c["count"]
        if cname == "ES":
            sp_count = cnt
        print(f"  {cname:10s}: {cnt:5,} requests")
    if sp_count == 0:
        sp_entry = next((c for c in countries_list if c["dimensions"]["clientCountryName"] == "ES"), None)
        if sp_entry:
            sp_count = sp_entry["count"]

    print(f"\n--- 🇪🇸 Spain (ES) Resident Activity ---")
    print(f"Total Requests from Spain: {sp_count:,}")
    sp_paths = zone_data.get("spainPaths", [])
    if sp_paths:
        print("Top Visited Pages from Spain:")
        for sp in sp_paths[:6]:
            path = sp["dimensions"]["clientRequestPath"]
            if not all_paths and any(path.endswith(ext) or path.startswith("/_astro/") for ext in ignored_exts):
                continue
            print(f"  {sp['count']:3,} reqs -> {path}")
    print(f"========================================================\n")


def main():
    parser = argparse.ArgumentParser(description="Cloudflare Edge & Traffic Analytics Monitor")
    parser.add_argument("--days", type=int, default=7, help="Number of days to inspect (default: 7)")
    parser.add_argument("--key", type=str, default=None, help="Cloudflare Global API Key")
    parser.add_argument("--email", type=str, default=None, help="Cloudflare Account Email")
    parser.add_argument("--token", type=str, default=None, help="Cloudflare API Token (Bearer)")
    parser.add_argument("--zone", type=str, default=DEFAULT_ZONE_ID, help="Cloudflare Zone Tag")
    parser.add_argument("--all-paths", action="store_true", help="Include static assets (.js, .css, images) in top paths")
    parser.add_argument("--verify-only", action="store_true", help="Verify credentials and exit")

    args = parser.parse_args()

    # Credential Resolution Order: CLI arg -> Environment Variable -> Default
    email = args.email or os.environ.get("CLOUDFLARE_EMAIL") or DEFAULT_EMAIL
    key = args.key or os.environ.get("CLOUDFLARE_API_KEY") or DEFAULT_KEY
    token = args.token or os.environ.get("CLOUDFLARE_API_TOKEN")

    # Step 1: Pre-Flight Verification
    headers, auth_type = verify_credentials(email, key, token)
    if not headers:
        sys.exit(1)

    if args.verify_only:
        print("Pre-flight verification passed. Exiting.")
        sys.exit(0)

    # Step 2: Fetch and render analytics
    fetch_zone_analytics(headers, args.zone, days=args.days, all_paths=args.all_paths)


if __name__ == "__main__":
    main()
