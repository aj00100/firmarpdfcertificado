#!/usr/bin/env python3
"""
Pulls complete 28-day GSC and Bing baseline data and exports raw JSON/CSV.
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

DEFAULT_SITE_URL = "sc-domain:firmarpdfcertificado.com"
FALLBACK_SITE_URL = "https://firmarpdfcertificado.com/"
DEFAULT_CREDS_PATH = "/data/data/com.termux/files/home/micro-tools/.gsc_credentials.json"
ALT_CREDS_PATH = "/sdcard/Download/gen-lang-client-0695474766-bd4b18ce3951.json"
BING_KEY_FILE = "/data/data/com.termux/files/home/micro-tools/.bing_api_key"
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

BING_API_KEY = load_bing_key()
BING_SITE_URL = "https://firmarpdfcertificado.com"

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def get_gsc_token():
    creds_path = DEFAULT_CREDS_PATH if os.path.exists(DEFAULT_CREDS_PATH) else ALT_CREDS_PATH
    with open(creds_path, "r", encoding="utf-8") as f:
        creds = json.load(f)
    client_email = creds["client_email"]
    private_key = creds["private_key"]

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iss": client_email,
        "scope": "https://www.googleapis.com/auth/webmasters.readonly",
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
        return json.loads(resp.read().decode("utf-8"))["access_token"], client_email

def query_gsc(token, body):
    encoded_site = urllib.parse.quote(DEFAULT_SITE_URL, safe="")
    url = f"https://www.googleapis.com/webmasters/v3/sites/{encoded_site}/searchAnalytics/query"
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8")).get("rows", [])
    except urllib.error.HTTPError as e:
        print("GSC Error:", e.read().decode("utf-8"))
        return []

def query_bing(endpoint):
    url = f"https://ssl.bing.com/webmaster/api.svc/json/{endpoint}?siteUrl={BING_SITE_URL}&apikey={BING_API_KEY}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json"
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8")).get("d", [])
    except Exception as e:
        print("Bing Error:", e)
        return []

def main():
    token, _ = get_gsc_token()
    today = datetime.now(timezone.utc).date()
    end_date = today - timedelta(days=2) # 2 days lag
    start_date = end_date - timedelta(days=27) # 28 days total
    start_str = start_date.strftime("%Y-%m-%d")
    end_str = end_date.strftime("%Y-%m-%d")

    print(f"Date Range (28 Days): {start_str} to {end_str}")

    # 1. GSC Pages
    pages_body = {
        "startDate": start_str,
        "endDate": end_str,
        "dimensions": ["page"],
        "rowLimit": 50
    }
    pages_rows = query_gsc(token, pages_body)

    # 2. GSC Top Queries for Site
    queries_body = {
        "startDate": start_str,
        "endDate": end_str,
        "dimensions": ["query"],
        "rowLimit": 30
    }
    top_queries_rows = query_gsc(token, queries_body)

    # 3. GSC Top Queries for FNMT Post
    fnmt_url = "https://firmarpdfcertificado.com/blog/como-renovar-certificado-digital-fnmt-por-internet-sin-cita-previa/"
    fnmt_body = {
        "startDate": start_str,
        "endDate": end_str,
        "dimensions": ["query"],
        "dimensionFilterGroups": [{
            "filters": [{
                "dimension": "page",
                "operator": "equals",
                "expression": fnmt_url
            }]
        }],
        "rowLimit": 20
    }
    fnmt_queries = query_gsc(token, fnmt_body)

    # 4. GSC Top Queries for iPhone Page
    iphone_url = "https://firmarpdfcertificado.com/firmar-pdf-certificado-mac-iphone/"
    iphone_body = {
        "startDate": start_str,
        "endDate": end_str,
        "dimensions": ["query"],
        "dimensionFilterGroups": [{
            "filters": [{
                "dimension": "page",
                "operator": "equals",
                "expression": iphone_url
            }]
        }],
        "rowLimit": 20
    }
    iphone_queries = query_gsc(token, iphone_body)

    # 5. GSC Top Queries for Comprobar Validez
    validez_url = "https://firmarpdfcertificado.com/comprobar-validez-certificado-digital/"
    validez_body = {
        "startDate": start_str,
        "endDate": end_str,
        "dimensions": ["query"],
        "dimensionFilterGroups": [{
            "filters": [{
                "dimension": "page",
                "operator": "equals",
                "expression": validez_url
            }]
        }],
        "rowLimit": 20
    }
    validez_queries = query_gsc(token, validez_body)

    # 6. Bing Stats
    bing_pages = query_bing("GetPageStats")
    bing_queries = query_bing("GetQueryStats")

    baseline_data = {
        "date_range": {
            "window_days": 28,
            "start_date": start_str,
            "end_date": end_str,
            "recorded_at": datetime.now(timezone.utc).isoformat()
        },
        "gsc": {
            "pages": pages_rows,
            "top_queries_site": top_queries_rows,
            "fnmt_post_queries": fnmt_queries,
            "iphone_page_queries": iphone_queries,
            "validez_page_queries": validez_queries
        },
        "bing": {
            "pages": bing_pages,
            "top_queries": bing_queries
        }
    }

    out_file = "/data/data/com.termux/files/home/firmarpdfcertificado/baseline_28days_raw.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=2, ensure_ascii=False)
    print(f"Baseline raw JSON written to: {out_file}")

if __name__ == "__main__":
    main()
