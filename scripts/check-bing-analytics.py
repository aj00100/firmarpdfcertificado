#!/usr/bin/env python3
"""
Bing Webmaster Traffic & SERP Analytics Monitor for firmarpdfcertificado.com
Features:
  - Pre-flight API Key verification and quota inspection (GetUrlSubmissionQuota)
  - Aggregated Page-level Performance (GetPageStats: Impressions, Clicks, CTR, Weighted Avg Position)
  - Aggregated Query-level Performance (GetQueryStats & GetPageQueryStats)
  - Search term filtering (e.g. --filter caducidad, --filter fnmt)
  - Daily Traffic timeline breakdown (GetRankAndTrafficStats)
API Scope vs UI Limitations:
  - Accessible via API: Pages, Queries, Timelines, Sitemaps, URL Submission, Crawl Errors, Keyword Research.
  - UI Only (No API): Device breakdown, Country breakdown, Copilot AI Citations, URL Inspection, Site Scan.
  - See full reference: ~/micro-tools/BING_API_CAPABILITIES_AND_LIMITATIONS.md
Usage:
  python3 scripts/check-bing-analytics.py [--pages] [--queries] [--filter term]
  BING_API_KEY="xxx" python3 scripts/check-bing-analytics.py
"""

import os
import sys
import time
import json
import argparse
import urllib.request
import urllib.error
from datetime import datetime, timezone

DEFAULT_SITE_URL = "https://firmarpdfcertificado.com"
TARGET_BING_KEY_FILE = "/data/data/com.termux/files/home/micro-tools/.bing_api_key_firmarpdfcertificado"
REPO_BING_KEY_FILE = os.path.join(os.path.dirname(__file__), "..", ".bing_api_key")
LEGACY_BING_KEY_FILE = "/data/data/com.termux/files/home/micro-tools/.bing_api_key"

def load_bing_key():
    if os.environ.get("BING_API_KEY"):
        return os.environ.get("BING_API_KEY").strip()
    for candidate in (TARGET_BING_KEY_FILE, REPO_BING_KEY_FILE, LEGACY_BING_KEY_FILE):
        if os.path.exists(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    val = f.read().strip()
                    if val:
                        return val
            except Exception:
                pass
    return ""

DEFAULT_API_KEY = load_bing_key()

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*"
}


def make_request(url, retries=3, timeout=15):
    """Executes a GET request against the Bing Webmaster API with retry backoff."""
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=BROWSER_HEADERS)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("d", []), resp.status
        except urllib.error.HTTPError as e:
            try:
                err_json = json.loads(e.read().decode("utf-8"))
                return err_json, e.code
            except Exception:
                return {"error": str(e)}, e.code
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1.0)
                continue
            return {"error": str(e)}, 0
    return {"error": "Max retries exceeded"}, 0


def verify_bing_credentials(site_url, api_key):
    """
    Pre-flight verification function:
    Checks API key validity and fetches URL submission quota.
    Handles rotated keys gracefully.
    """
    print("🔍 [Pre-Flight] Verifying Bing Webmaster API Key...")
    url = f"https://ssl.bing.com/webmaster/api.svc/json/GetUrlSubmissionQuota?siteUrl={site_url}&apikey={api_key}"
    res, status = make_request(url)

    if status == 200 and isinstance(res, dict) and "DailyQuota" in res:
        daily = res.get("DailyQuota")
        monthly = res.get("MonthlyQuota")
        print("✅ Bing Webmaster API Key verified!")
        print(f"   Daily Submission Quota Remaining:   {daily}")
        print(f"   Monthly Submission Quota Remaining: {monthly}\n")
        return True
    else:
        print(f"\n❌ Bing API Key Verification FAILED (HTTP {status})!")
        print(f"   Response: {res}")
        print("\n💡 The API Key may have been rotated. To supply a new key, run:")
        print("   export BING_API_KEY='your_new_key'")
        print("   python3 scripts/check-bing-analytics.py\n")
        return False


def parse_bing_date(date_str):
    """Parses Microsoft /Date(1793318400000)/ timestamp format into readable date."""
    if not date_str or not isinstance(date_str, str):
        return ""
    try:
        ts_ms = int(date_str.strip("/Date()").split("+")[0].split("-")[0])
        return datetime.fromtimestamp(ts_ms / 1000.0, timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return date_str


def fetch_page_stats(site_url, api_key, filter_term=None):
    """Fetches and aggregates page-level metrics from GetPageStats."""
    url = f"https://ssl.bing.com/webmaster/api.svc/json/GetPageStats?siteUrl={site_url}&apikey={api_key}"
    records, status = make_request(url)

    if status != 200 or not isinstance(records, list):
        print(f"❌ Failed to fetch Page Stats (HTTP {status}): {records}")
        return

    pages_agg = {}
    for r in records:
        page_url = r.get("Query", "").strip()
        if filter_term and filter_term.lower() not in page_url.lower():
            continue

        impr = r.get("Impressions", 0)
        clicks = r.get("Clicks", 0)
        pos = r.get("AvgImpressionPosition", 0)

        if page_url not in pages_agg:
            pages_agg[page_url] = {"impressions": 0, "clicks": 0, "pos_weight": 0}

        pages_agg[page_url]["impressions"] += impr
        pages_agg[page_url]["clicks"] += clicks
        pages_agg[page_url]["pos_weight"] += (pos * impr)

    print("=========================================================================================")
    print("📄 BING WEBMASTER — PAGE-LEVEL PERFORMANCE")
    print("=========================================================================================")
    print(f"{'Impressions':>11} | {'Clicks':>6} | {'CTR':>7} | {'Avg Pos':>7} | Page URL")
    print("-" * 89)

    sorted_pages = sorted(pages_agg.items(), key=lambda x: x[1]["impressions"], reverse=True)
    total_impr = sum(p[1]["impressions"] for p in sorted_pages)
    total_clicks = sum(p[1]["clicks"] for p in sorted_pages)

    for page_url, stats in sorted_pages:
        impr = stats["impressions"]
        clicks = stats["clicks"]
        ctr = (clicks / impr * 100) if impr else 0.0
        avg_pos = (stats["pos_weight"] / impr) if impr else 0.0

        display_path = page_url.replace(site_url, "")
        if display_path == "":
            display_path = "/ (Homepage)"

        print(f"{impr:11,d} | {clicks:6,d} | {ctr:6.2f}% | {avg_pos:7.1f} | {display_path}")

    print("-" * 89)
    total_ctr = (total_clicks / total_impr * 100) if total_impr else 0.0
    print(f"{total_impr:11,d} | {total_clicks:6,d} | {total_ctr:6.2f}% | {'--':>7} | TOTALS ({len(sorted_pages)} Ranking Pages)")
    print("=========================================================================================\n")


def fetch_query_stats(site_url, api_key, filter_term=None, limit=25):
    """Fetches and aggregates query-level metrics from GetQueryStats."""
    url = f"https://ssl.bing.com/webmaster/api.svc/json/GetQueryStats?siteUrl={site_url}&apikey={api_key}"
    records, status = make_request(url)

    if status != 200 or not isinstance(records, list):
        print(f"❌ Failed to fetch Query Stats (HTTP {status}): {records}")
        return

    queries_agg = {}
    for r in records:
        query_text = r.get("Query", "").strip()
        if filter_term and filter_term.lower() not in query_text.lower():
            continue

        impr = r.get("Impressions", 0)
        clicks = r.get("Clicks", 0)
        pos = r.get("AvgImpressionPosition", 0)

        if query_text not in queries_agg:
            queries_agg[query_text] = {"impressions": 0, "clicks": 0, "pos_weight": 0}

        queries_agg[query_text]["impressions"] += impr
        queries_agg[query_text]["clicks"] += clicks
        queries_agg[query_text]["pos_weight"] += (pos * impr)

    print("=========================================================================================")
    print(f"🔍 BING WEBMASTER — QUERY-LEVEL PERFORMANCE {f'(Filter: \"{filter_term}\")' if filter_term else ''}")
    print("=========================================================================================")
    print(f"{'Impressions':>11} | {'Clicks':>6} | {'CTR':>7} | {'Avg Pos':>7} | Search Query")
    print("-" * 89)

    sorted_queries = sorted(queries_agg.items(), key=lambda x: x[1]["impressions"], reverse=True)
    for query_text, stats in sorted_queries[:limit]:
        impr = stats["impressions"]
        clicks = stats["clicks"]
        ctr = (clicks / impr * 100) if impr else 0.0
        avg_pos = (stats["pos_weight"] / impr) if impr else 0.0
        print(f"{impr:11,d} | {clicks:6,d} | {ctr:6.2f}% | {avg_pos:7.1f} | {query_text}")

    remaining = len(sorted_queries) - limit
    if remaining > 0:
        print(f"... and {remaining} more long-tail queries (use --limit {len(sorted_queries)} or --filter to see all)")
    print("=========================================================================================\n")


def fetch_traffic_timeline(site_url, api_key):
    """Fetches daily clicks & impressions timeline from GetRankAndTrafficStats."""
    url = f"https://ssl.bing.com/webmaster/api.svc/json/GetRankAndTrafficStats?siteUrl={site_url}&apikey={api_key}"
    records, status = make_request(url)

    if status != 200 or not isinstance(records, list):
        return

    print("=========================================================================================")
    print("📈 BING WEBMASTER — DAILY TRAFFIC TIMELINE")
    print("=========================================================================================")
    print(f"{'Date':^12} | {'Impressions':>12} | {'Clicks':>8} | Visual Timeline")
    print("-" * 65)

    timeline = []
    for r in records:
        date_formatted = parse_bing_date(r.get("Date"))
        impr = r.get("Impressions", 0)
        clicks = r.get("Clicks", 0)
        if date_formatted:
            timeline.append((date_formatted, impr, clicks))

    timeline = sorted(timeline, key=lambda x: x[0])
    max_impr = max((t[1] for t in timeline), default=1)

    for d, impr, clicks in timeline[-14:]:
        bar = "█" * max(1, int(impr / max(1, max_impr) * 20)) if impr > 0 else "· (Pipeline Lag / 0)"
        print(f"{d:^12} | {impr:12,d} | {clicks:8,d} | {bar}")
    print("=========================================================================================\n")


def fetch_keyword_research(site_url, api_key, keyword):
    """Queries Bing internal keyword research database via GetKeywordStats."""
    import urllib.parse
    q_enc = urllib.parse.quote(keyword)
    url = f"https://ssl.bing.com/webmaster/api.svc/json/GetKeywordStats?q={q_enc}&siteUrl={site_url}&apikey={api_key}"
    records, status = make_request(url)

    if status != 200 or not isinstance(records, list):
        print(f"❌ Failed to fetch Keyword Research for '{keyword}' (HTTP {status}): {records}")
        return

    print("=========================================================================================")
    print(f"🔑 BING KEYWORD RESEARCH — 25-WEEK SEARCH VOLUME: \"{keyword}\"")
    print("=========================================================================================")
    if not records:
        print("No historical search volume returned by Bing for this exact phrase.")
        print("💡 Try a shorter torso keyword (e.g. 'validar firma digital' instead of full long-tail).")
        print("=========================================================================================\n")
        return

    print(f"{'Week Ending':^12} | {'Exact Searches':>14} | {'Broad Searches':>14} | Weekly Trend")
    print("-" * 65)

    total_exact = sum(r.get("Impressions", 0) for r in records)
    total_broad = sum(r.get("BroadImpressions", 0) for r in records)
    recent_exact = sum(r.get("Impressions", 0) for r in records[-4:])
    monthly_est = int(recent_exact * (4.33 / 4.0))
    max_impr = max((x.get("Impressions", 0) for x in records), default=1)

    for r in records[-12:]:  # Show last 12 weeks
        date_str = parse_bing_date(r.get("Date"))
        exact = r.get("Impressions", 0)
        broad = r.get("BroadImpressions", 0)
        bar = "█" * max(1, int(exact / max(1, max_impr) * 15)) if exact > 0 else "·"
        print(f"{date_str:^12} | {exact:14,d} | {broad:14,d} | {bar}")

    print("-" * 65)
    print(f"Total 25-Week Searches:  {total_exact:,d} (Broad: {total_broad:,d})")
    print(f"Last 4 Weeks Volume:     {recent_exact:,d}")
    print(f"Estimated Monthly Rate:  ~{monthly_est:,d} searches/month on Bing")
    print("=========================================================================================\n")


def main():
    parser = argparse.ArgumentParser(description="Bing Webmaster Traffic & SERP Analytics Monitor")
    parser.add_argument("--key", type=str, default=None, help="Bing Webmaster API Key")
    parser.add_argument("--site", type=str, default=DEFAULT_SITE_URL, help="Site URL")
    parser.add_argument("--pages", action="store_true", help="Display only page-level metrics")
    parser.add_argument("--queries", action="store_true", help="Display only query-level metrics")
    parser.add_argument("--research", type=str, default=None, help="Query Bing Keyword Research volume for a keyword")
    parser.add_argument("--filter", type=str, default=None, help="Filter pages or queries by keyword")
    parser.add_argument("--limit", type=int, default=25, help="Number of queries to display (default: 25)")
    parser.add_argument("--verify-only", action="store_true", help="Verify credentials and quota, then exit")

    args = parser.parse_args()

    api_key = args.key or os.environ.get("BING_API_KEY") or DEFAULT_API_KEY

    # 1. Pre-flight verification
    if not verify_bing_credentials(args.site, api_key):
        sys.exit(1)

    if args.verify_only:
        sys.exit(0)

    # 2. Keyword research standalone mode
    if args.research:
        fetch_keyword_research(args.site, api_key, args.research)
        return

    # 3. Render requested sections
    show_all = not (args.pages or args.queries)

    if show_all or args.pages:
        fetch_page_stats(args.site, api_key, filter_term=args.filter)

    if show_all or args.queries:
        fetch_query_stats(args.site, api_key, filter_term=args.filter, limit=args.limit)

    if show_all:
        fetch_traffic_timeline(args.site, api_key)


if __name__ == "__main__":
    main()
