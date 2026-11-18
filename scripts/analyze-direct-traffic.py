#!/usr/bin/env python3
"""
Segment and inspect Direct Traffic in GA4 for firmarpdfcertificado.com
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

DEFAULT_PROPERTY_ID = "561091170"
DEFAULT_CREDS_PATH = "/data/data/com.termux/files/home/micro-tools/.gsc_credentials.json"
ALT_CREDS_PATH = "/sdcard/Download/gen-lang-client-0695474766-bd4b18ce3951.json"

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def get_token(creds_path: str):
    if not os.path.exists(creds_path):
        creds_path = ALT_CREDS_PATH
    with open(creds_path, "r", encoding="utf-8") as f:
        creds = json.load(f)
    client_email = creds["client_email"]
    private_key = creds["private_key"]

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iss": client_email,
        "scope": "https://www.googleapis.com/auth/analytics.readonly",
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

def run_report(token: str, body: dict):
    url = f"https://analyticsdata.googleapis.com/v1beta/properties/{DEFAULT_PROPERTY_ID}:runReport"
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8")), 200
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode("utf-8")), e.code

def main():
    token, email = get_token(DEFAULT_CREDS_PATH)
    print(f"Authenticated as: {email}")

    # 1. Direct Traffic by Country & City
    print("\n" + "="*80)
    print("🌍 1. DIRECT TRAFFIC BY COUNTRY & CITY (Past 28 Days)")
    print("="*80)
    body_country = {
        "dateRanges": [{"startDate": "28daysAgo", "endDate": "today"}],
        "dimensions": [{"name": "country"}, {"name": "city"}],
        "metrics": [
            {"name": "activeUsers"},
            {"name": "sessions"},
            {"name": "engagedSessions"},
            {"name": "userEngagementDuration"}
        ],
        "dimensionFilter": {
            "filter": {
                "fieldName": "sessionSource",
                "stringFilter": {"value": "(direct)", "matchType": "EXACT"}
            }
        },
        "limit": 30
    }
    res, status = run_report(token, body_country)
    if status == 200:
        print(f"{'Country':<20} | {'City':<20} | {'Users':>6} | {'Sess':>6} | {'EngSess':>7} | {'AvgEngTime':>10}")
        print("-" * 78)
        for r in res.get("rows", []):
            country = r["dimensionValues"][0]["value"]
            city = r["dimensionValues"][1]["value"]
            users = int(r["metricValues"][0]["value"])
            sess = int(r["metricValues"][1]["value"])
            eng_sess = int(r["metricValues"][2]["value"])
            dur = float(r["metricValues"][3]["value"])
            avg_time = f"{int(dur / max(1, users))}s" if users else "0s"
            print(f"{country:<20} | {city:<20} | {users:6d} | {sess:6d} | {eng_sess:7d} | {avg_time:>10}")

    # 2. Direct Traffic by Device, OS & Browser
    print("\n" + "="*80)
    print("📱 2. DIRECT TRAFFIC BY DEVICE, OS & BROWSER (Past 28 Days)")
    print("="*80)
    body_device = {
        "dateRanges": [{"startDate": "28daysAgo", "endDate": "today"}],
        "dimensions": [{"name": "deviceCategory"}, {"name": "operatingSystem"}, {"name": "browser"}],
        "metrics": [
            {"name": "activeUsers"},
            {"name": "sessions"},
            {"name": "engagedSessions"},
            {"name": "userEngagementDuration"}
        ],
        "dimensionFilter": {
            "filter": {
                "fieldName": "sessionSource",
                "stringFilter": {"value": "(direct)", "matchType": "EXACT"}
            }
        },
        "limit": 30
    }
    res, status = run_report(token, body_device)
    if status == 200:
        print(f"{'Device':<10} | {'OS':<15} | {'Browser':<15} | {'Users':>6} | {'Sess':>6} | {'EngSess':>7} | {'AvgEngTime':>10}")
        print("-" * 80)
        for r in res.get("rows", []):
            dev = r["dimensionValues"][0]["value"]
            os_name = r["dimensionValues"][1]["value"]
            browser = r["dimensionValues"][2]["value"]
            users = int(r["metricValues"][0]["value"])
            sess = int(r["metricValues"][1]["value"])
            eng_sess = int(r["metricValues"][2]["value"])
            dur = float(r["metricValues"][3]["value"])
            avg_time = f"{int(dur / max(1, users))}s" if users else "0s"
            print(f"{dev:<10} | {os_name:<15} | {browser:<15} | {users:6d} | {sess:6d} | {eng_sess:7d} | {avg_time:>10}")

    # 3. Direct Traffic Landing Page
    print("\n" + "="*80)
    print("🚪 3. DIRECT TRAFFIC BY LANDING PAGE (Past 28 Days)")
    print("="*80)
    body_lp = {
        "dateRanges": [{"startDate": "28daysAgo", "endDate": "today"}],
        "dimensions": [{"name": "landingPagePlusQueryString"}],
        "metrics": [
            {"name": "activeUsers"},
            {"name": "sessions"},
            {"name": "engagedSessions"},
            {"name": "userEngagementDuration"}
        ],
        "dimensionFilter": {
            "filter": {
                "fieldName": "sessionSource",
                "stringFilter": {"value": "(direct)", "matchType": "EXACT"}
            }
        },
        "limit": 30
    }
    res, status = run_report(token, body_lp)
    if status == 200:
        print(f"{'Users':>6} | {'Sess':>6} | {'EngSess':>7} | {'AvgEngTime':>10} | Landing Page")
        print("-" * 80)
        for r in res.get("rows", []):
            lp = r["dimensionValues"][0]["value"]
            users = int(r["metricValues"][0]["value"])
            sess = int(r["metricValues"][1]["value"])
            eng_sess = int(r["metricValues"][2]["value"])
            dur = float(r["metricValues"][3]["value"])
            avg_time = f"{int(dur / max(1, users))}s" if users else "0s"
            print(f"{users:6d} | {sess:6d} | {eng_sess:7d} | {avg_time:>10} | {lp}")

    # 4. Conversion Events by Channel (Search vs Direct vs Referral)
    print("\n" + "="*80)
    print("🎯 4. CONVERSIONS & EVENTS BY CHANNEL GROUP (Past 28 Days)")
    print("="*80)
    body_events = {
        "dateRanges": [{"startDate": "28daysAgo", "endDate": "today"}],
        "dimensions": [{"name": "sessionDefaultChannelGroup"}, {"name": "eventName"}],
        "metrics": [
            {"name": "eventCount"},
            {"name": "totalUsers"}
        ],
        "limit": 100
    }
    res, status = run_report(token, body_events)
    if status == 200:
        print(f"{'Channel Group':<20} | {'Event Count':>12} | {'Users':>6} | Event Name")
        print("-" * 70)
        for r in res.get("rows", []):
            ch = r["dimensionValues"][0]["value"]
            ev = r["dimensionValues"][1]["value"]
            cnt = int(r["metricValues"][0]["value"])
            users = int(r["metricValues"][1]["value"])
            if ev in ["sign_success", "validator_success", "sign_attempt", "tool_view", "pdf_loaded", "p12_loaded", "page_view", "session_start", "first_visit"]:
                print(f"{ch:<20} | {cnt:12d} | {users:6d} | {ev}")

if __name__ == "__main__":
    main()
