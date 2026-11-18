#!/usr/bin/env python3
"""
Comprehensive Automated Baseline Capture for firmarpdfcertificado.com
Captures 28-day baseline from GSC, Bing, GA4, and Cloudflare.
Saves raw CSV and JSON artifacts to baselines/2026-11-18/.
"""

import os
import sys
import json
import time
import base64
import tempfile
import subprocess
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone

# Target Directories & Paths
REPO_DIR = "/data/data/com.termux/files/home/firmarpdfcertificado"
BASELINE_DIR = os.path.join(REPO_DIR, "baselines", "2026-11-18")
os.makedirs(BASELINE_DIR, exist_ok=True)

# Credentials & Constants
GSC_CREDS_PATH = "/data/data/com.termux/files/home/micro-tools/.gsc_credentials.json"
ALT_CREDS_PATH = "/sdcard/Download/gen-lang-client-0695474766-bd4b18ce3951.json"
GA4_PROPERTY_ID = "561091170"
BING_SITE_URL = "https://firmarpdfcertificado.com"
BING_KEY_FILE = "/data/data/com.termux/files/home/micro-tools/.bing_api_key"
CF_CREDS_FILE = "/data/data/com.termux/files/home/micro-tools/.cloudflare_credentials.json"

def load_bing_key():
    if os.environ.get("BING_API_KEY"):
        return os.environ.get("BING_API_KEY").strip()
    if os.path.exists(BING_KEY_FILE):
        try:
            with open(BING_KEY_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    return ""

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

BING_API_KEY = load_bing_key()
CF_ZONE_ID = "9ae01356cb36f15cd5f0135f6acc4af1"
CF_EMAIL, CF_KEY = load_cf_creds()

TARGET_PAGES = [
    "/comprobar-validez-certificado-digital/",
    "/firmar-pdf-certificado-mac-iphone/",
    "/blog/como-renovar-certificado-digital-fnmt-por-internet-sin-cita-previa/"
]

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def get_google_token(scope: str):
    path = GSC_CREDS_PATH if os.path.exists(GSC_CREDS_PATH) else ALT_CREDS_PATH
    with open(path, "r", encoding="utf-8") as f:
        creds = json.load(f)
    client_email = creds["client_email"]
    private_key = creds["private_key"]

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iss": client_email,
        "scope": scope,
        "aud": "https://oauth2.googleapis.com/token",
        "exp": now + 3600,
        "iat": now
    }
    unsigned_jwt = b64url(json.dumps(header).encode("utf-8")) + "." + b64url(json.dumps(payload).encode("utf-8"))

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=True) as kf:
        kf.write(private_key)
        kf.flush()
        p = subprocess.Popen(
            ["openssl", "dgst", "-sha256", "-sign", kf.name],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        sig, err = p.communicate(input=unsigned_jwt.encode("utf-8"))

    signed_jwt = unsigned_jwt + "." + b64url(sig)
    token_url = "https://oauth2.googleapis.com/token"
    post_data = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": signed_jwt
    }).encode("utf-8")
    req = urllib.request.Request(token_url, data=post_data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))["access_token"]

def query_gsc(token, body):
    site_url = "sc-domain:firmarpdfcertificado.com"
    encoded_site = urllib.parse.quote(site_url, safe="")
    url = f"https://www.googleapis.com/webmasters/v3/sites/{encoded_site}/searchAnalytics/query"
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    })
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode("utf-8")).get("rows", [])
        except Exception as e:
            if attempt == 2:
                print(f"GSC query failed: {e}")
                return []
            time.sleep(1)

def query_ga4(token, body):
    url = f"https://analyticsdata.googleapis.com/v1beta/properties/{GA4_PROPERTY_ID}:runReport"
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    })
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            if attempt == 2:
                print(f"GA4 query failed: {e}")
                return {}
            time.sleep(1)

def query_bing(endpoint):
    url = f"https://ssl.bing.com/webmaster/api.svc/json/{endpoint}?siteUrl={BING_SITE_URL}&apikey={BING_API_KEY}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json"
    })
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode("utf-8")).get("d", [])
        except Exception as e:
            if attempt == 2:
                print(f"Bing query failed: {e}")
                return []
            time.sleep(1)

def query_cf(query, variables):
    headers = {
        "X-Auth-Email": CF_EMAIL,
        "X-Auth-Key": CF_KEY,
        "User-Agent": "CFAnalytics/1.0",
        "Content-Type": "application/json"
    }
    payload = {"query": query, "variables": variables}
    req = urllib.request.Request("https://api.cloudflare.com/client/v4/graphql", data=json.dumps(payload).encode("utf-8"), headers=headers)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("data", {}).get("viewer", {}).get("zones", [{}])[0]
        except Exception as e:
            if attempt == 2:
                print(f"CF query failed: {e}")
                return {}
            time.sleep(2)

def save_csv(filename, header, rows):
    path = os.path.join(BASELINE_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(",".join(header) + "\n")
        for r in rows:
            f.write(",".join(str(item) for item in r) + "\n")
    return path

def main():
    print("🚀 Starting Automated Baseline Capture...")
    snapshot = {"captured_at": datetime.now(timezone.utc).isoformat(), "sources": {}}

    # =========================================================================
    # 1. Google Search Console (28-day window ending on latest available date)
    # =========================================================================
    print("▶ 1/4 Fetching GSC Data...")
    gsc_token = get_google_token("https://www.googleapis.com/auth/webmasters.readonly")
    today = datetime.now(timezone.utc).date()
    gsc_end = today - timedelta(days=2) # 2-day lag
    gsc_start = gsc_end - timedelta(days=27)
    gsc_start_str = gsc_start.strftime("%Y-%m-%d")
    gsc_end_str = gsc_end.strftime("%Y-%m-%d")

    # Target pages
    gsc_pages_raw = query_gsc(gsc_token, {
        "startDate": gsc_start_str, "endDate": gsc_end_str,
        "dimensions": ["page"], "rowLimit": 50
    })
    target_pages_rows = []
    for r in gsc_pages_raw:
        path = r["keys"][0].replace("https://firmarpdfcertificado.com", "") or "/"
        target_pages_rows.append([
            path, r["impressions"], r["clicks"], f"{r['ctr']*100:.2f}", f"{r['position']:.1f}"
        ])
    save_csv("gsc_all_pages.csv", ["page_path", "impressions", "clicks", "ctr_percent", "avg_position"], target_pages_rows)

    target_3_pages = [r for r in target_pages_rows if r[0] in TARGET_PAGES]
    save_csv("gsc_target_3_pages.csv", ["page_path", "impressions", "clicks", "ctr_percent", "avg_position"], target_3_pages)

    # Top 25 Queries Overall
    gsc_top25_raw = query_gsc(gsc_token, {
        "startDate": gsc_start_str, "endDate": gsc_end_str,
        "dimensions": ["query"], "rowLimit": 25
    })
    gsc_top25_rows = []
    for r in gsc_top25_raw:
        q = '"' + r["keys"][0].replace('"', '""') + '"'
        gsc_top25_rows.append([q, r["impressions"], r["clicks"], f"{r['ctr']*100:.2f}", f"{r['position']:.1f}"])
    save_csv("gsc_top25_queries.csv", ["query", "impressions", "clicks", "ctr_percent", "avg_position"], gsc_top25_rows)

    # FNMT Post Queries (Top 10)
    fnmt_raw = query_gsc(gsc_token, {
        "startDate": gsc_start_str, "endDate": gsc_end_str,
        "dimensions": ["query"],
        "dimensionFilterGroups": [{
            "filters": [{"dimension": "page", "operator": "equals", "expression": "https://firmarpdfcertificado.com/blog/como-renovar-certificado-digital-fnmt-por-internet-sin-cita-previa/"}]
        }],
        "rowLimit": 10
    })
    fnmt_rows = []
    for r in fnmt_raw:
        q = '"' + r["keys"][0].replace('"', '""') + '"'
        fnmt_rows.append([q, r["impressions"], r["clicks"], f"{r['ctr']*100:.2f}", f"{r['position']:.1f}"])
    save_csv("gsc_fnmt_top10_queries.csv", ["query", "impressions", "clicks", "ctr_percent", "avg_position"], fnmt_rows)

    # iPhone Page Queries (Top 10)
    iphone_raw = query_gsc(gsc_token, {
        "startDate": gsc_start_str, "endDate": gsc_end_str,
        "dimensions": ["query"],
        "dimensionFilterGroups": [{
            "filters": [{"dimension": "page", "operator": "equals", "expression": "https://firmarpdfcertificado.com/firmar-pdf-certificado-mac-iphone/"}]
        }],
        "rowLimit": 10
    })
    iphone_rows = []
    for r in iphone_raw:
        q = '"' + r["keys"][0].replace('"', '""') + '"'
        iphone_rows.append([q, r["impressions"], r["clicks"], f"{r['ctr']*100:.2f}", f"{r['position']:.1f}"])
    save_csv("gsc_iphone_top10_queries.csv", ["query", "impressions", "clicks", "ctr_percent", "avg_position"], iphone_rows)

    snapshot["sources"]["gsc"] = {
        "date_range": f"{gsc_start_str} to {gsc_end_str} (28 days)",
        "target_3_pages": target_3_pages,
        "top25_queries": gsc_top25_rows,
        "fnmt_top10_queries": fnmt_rows,
        "iphone_top10_queries": iphone_rows
    }

    # =========================================================================
    # 2. Bing Webmaster Tools (Rolling 30-day API window)
    # =========================================================================
    print("▶ 2/4 Fetching Bing WMT Data...")
    bing_pages_raw = query_bing("GetPageStats")
    bing_queries_raw = query_bing("GetQueryStats")

    # Aggregate Bing pages
    bing_pages_agg = {}
    for r in bing_pages_raw:
        p = r.get("Query", "").replace("https://firmarpdfcertificado.com", "") or "/"
        impr = r.get("Impressions", 0)
        clicks = r.get("Clicks", 0)
        pos = r.get("AvgImpressionPosition", 0)
        if p not in bing_pages_agg:
            bing_pages_agg[p] = {"impr": 0, "clicks": 0, "pos_w": 0}
        bing_pages_agg[p]["impr"] += impr
        bing_pages_agg[p]["clicks"] += clicks
        bing_pages_agg[p]["pos_w"] += (pos * impr)

    bing_pages_rows = []
    for p, s in sorted(bing_pages_agg.items(), key=lambda x: x[1]["impr"], reverse=True):
        impr = s["impr"]
        clicks = s["clicks"]
        ctr = (clicks / impr * 100) if impr else 0.0
        pos = (s["pos_w"] / impr) if impr else 0.0
        bing_pages_rows.append([p, impr, clicks, f"{ctr:.2f}", f"{pos:.1f}"])
    save_csv("bing_all_pages.csv", ["page_path", "impressions", "clicks", "ctr_percent", "avg_position"], bing_pages_rows)

    # Bing Top 25 Queries
    bing_q_agg = {}
    for r in bing_queries_raw:
        q = r.get("Query", "").strip()
        impr = r.get("Impressions", 0)
        clicks = r.get("Clicks", 0)
        pos = r.get("AvgImpressionPosition", 0)
        if q not in bing_q_agg:
            bing_q_agg[q] = {"impr": 0, "clicks": 0, "pos_w": 0}
        bing_q_agg[q]["impr"] += impr
        bing_q_agg[q]["clicks"] += clicks
        bing_q_agg[q]["pos_w"] += (pos * impr)

    bing_q_rows = []
    for q, s in sorted(bing_q_agg.items(), key=lambda x: x[1]["impr"], reverse=True)[:25]:
        impr = s["impr"]
        clicks = s["clicks"]
        ctr = (clicks / impr * 100) if impr else 0.0
        pos = (s["pos_w"] / impr) if impr else 0.0
        q_fmt = '"' + q.replace('"', '""') + '"'
        bing_q_rows.append([q_fmt, impr, clicks, f"{ctr:.2f}", f"{pos:.1f}"])
    save_csv("bing_top25_queries.csv", ["query", "impressions", "clicks", "ctr_percent", "avg_position"], bing_q_rows)

    snapshot["sources"]["bing"] = {
        "date_range": "30-day rolling aggregate (latest available)",
        "pages": bing_pages_rows[:10],
        "top25_queries": bing_q_rows
    }

    # =========================================================================
    # 3. Google Analytics 4 (28-day window)
    # =========================================================================
    print("▶ 3/4 Fetching GA4 Data...")
    ga4_token = get_google_token("https://www.googleapis.com/auth/analytics.readonly")

    # Events split by Channel (Organic vs Direct)
    ga4_events_res = query_ga4(ga4_token, {
        "dateRanges": [{"startDate": "28daysAgo", "endDate": "today"}],
        "dimensions": [{"name": "sessionDefaultChannelGroup"}, {"name": "eventName"}],
        "metrics": [{"name": "eventCount"}, {"name": "totalUsers"}],
        "limit": 100
    })
    ga4_event_rows = []
    for r in ga4_events_res.get("rows", []):
        ch = r["dimensionValues"][0]["value"]
        ev = r["dimensionValues"][1]["value"]
        cnt = int(r["metricValues"][0]["value"])
        users = int(r["metricValues"][1]["value"])
        ga4_event_rows.append([ch, ev, cnt, users])
    save_csv("ga4_events_by_channel.csv", ["channel_group", "event_name", "event_count", "total_users"], ga4_event_rows)

    # Direct traffic by country & landing page
    ga4_geo_res = query_ga4(ga4_token, {
        "dateRanges": [{"startDate": "28daysAgo", "endDate": "today"}],
        "dimensions": [{"name": "country"}, {"name": "landingPagePlusQueryString"}],
        "metrics": [{"name": "activeUsers"}, {"name": "sessions"}, {"name": "userEngagementDuration"}],
        "dimensionFilter": {
            "filter": {"fieldName": "sessionSource", "stringFilter": {"value": "(direct)", "matchType": "EXACT"}}
        },
        "limit": 100
    })
    ga4_geo_rows = []
    for r in ga4_geo_res.get("rows", []):
        country = r["dimensionValues"][0]["value"]
        lp = r["dimensionValues"][1]["value"]
        users = int(r["metricValues"][0]["value"])
        sess = int(r["metricValues"][1]["value"])
        dur = float(r["metricValues"][2]["value"])
        avg_time = int(dur / max(1, users))
        ga4_geo_rows.append([country, lp, users, sess, f"{avg_time}s"])
    save_csv("ga4_direct_geo_landing.csv", ["country", "landing_page", "active_users", "sessions", "avg_engagement_time"], ga4_geo_rows)

    snapshot["sources"]["ga4"] = {
        "date_range": "Past 28 days (28daysAgo to today)",
        "events": ga4_event_rows,
        "direct_traffic": ga4_geo_rows[:20]
    }

    # =========================================================================
    # 4. Cloudflare Analytics (Past 28 days)
    # =========================================================================
    print("▶ 4/4 Fetching Cloudflare Edge Data...")
    cf_end_dt = datetime.now(timezone.utc)
    cf_since_dt = cf_end_dt - timedelta(days=28)
    cf_since = cf_since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    cf_until = cf_end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    cf_q = """
    query GetCFData($zoneTag: String!, $since: String!, $until: String!) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          daily: httpRequestsAdaptiveGroups(
            limit: 35
            filter: { datetime_geq: $since, datetime_leq: $until }
            orderBy: [count_DESC]
          ) {
            count
            dimensions { date }
          }
          statusCodes: httpRequestsAdaptiveGroups(
            limit: 20
            filter: { datetime_geq: $since, datetime_leq: $until }
            orderBy: [count_DESC]
          ) {
            count
            dimensions { edgeResponseStatus }
          }
        }
      }
    }
    """
    cf_res = query_cf(cf_q, {"zoneTag": CF_ZONE_ID, "since": cf_since, "until": cf_until})
    cf_daily_rows = []
    if cf_res:
        daily_list = sorted(cf_res.get("daily", []), key=lambda x: x["dimensions"]["date"])
        for d in daily_list:
            cf_daily_rows.append([d["dimensions"]["date"], d["count"]])
    save_csv("cloudflare_daily_requests.csv", ["date", "requests"], cf_daily_rows)

    cf_status_rows = []
    eh_504_count = 0
    if cf_res:
        for s in cf_res.get("statusCodes", []):
            st = s["dimensions"]["edgeResponseStatus"]
            cnt = s["count"]
            if st == 504:
                eh_504_count = cnt
            cf_status_rows.append([st, cnt])
    save_csv("cloudflare_status_codes.csv", ["status_code", "count"], cf_status_rows)

    snapshot["sources"]["cloudflare"] = {
        "date_range": f"{cf_since[:10]} to {cf_until[:10]} (28 days)",
        "total_requests": sum(r[1] for r in cf_daily_rows),
        "early_hints_504_count": eh_504_count,
        "daily_requests": cf_daily_rows,
        "status_codes": cf_status_rows
    }

    # =========================================================================
    # Write Full Consolidated Snapshot JSON
    # =========================================================================
    json_path = os.path.join(BASELINE_DIR, "baseline_full_snapshot.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)
    print(f"\n✅ All baseline files successfully written to: {BASELINE_DIR}")

if __name__ == "__main__":
    main()
