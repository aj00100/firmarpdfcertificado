#!/usr/bin/env python3
"""
Google Analytics 4 (GA4) Telemetry & Conversion Monitor for firmarpdfcertificado.com
Features:
  - 100% Zero-dependency Service Account JWT authentication using OpenSSL CLI
  - Pre-flight credentials & GA4 Property verification (Property ID: 561091170)
  - Top Pages Performance (Views, Active Users, Engagement Duration)
  - Custom Event & Conversion Tracking (sign_success, tool_view, validator_success, etc.)
  - Acquisition Channels (Organic Search, Direct, Referral)
  - Device & OS Breakdown (Mobile vs. Desktop vs. Tablet, iOS vs. Android vs. Windows)
Usage:
  python3 scripts/check-ga4-analytics.py [--verify-only]
  python3 scripts/check-ga4-analytics.py [--pages] [--events] [--sources] [--devices] [--days 28]
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

DEFAULT_PROPERTY_ID = "561091170"
DEFAULT_CREDS_PATH = "/data/data/com.termux/files/home/micro-tools/.gsc_credentials.json"
ALT_CREDS_PATH = "/sdcard/Download/gen-lang-client-0695474766-bd4b18ce3951.json"


def b64url(data: bytes) -> str:
    """Encodes bytes into URL-safe base64 string without trailing '='."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def get_ga4_access_token(creds_path: str) -> tuple[str, str]:
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
        "scope": "https://www.googleapis.com/auth/analytics.readonly",
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


def run_ga4_report(token: str, property_id: str, body: dict) -> tuple[dict, int]:
    """Calls Google Analytics Data API v1beta runReport endpoint."""
    url = f"https://analyticsdata.googleapis.com/v1beta/properties/{property_id}:runReport"

    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data, 200
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        try:
            return json.loads(err_msg), e.code
        except Exception:
            return {"error": err_msg}, e.code
    except Exception as e:
        return {"error": str(e)}, 0


def verify_ga4_setup(token: str, property_id: str, client_email: str) -> bool:
    """Performs pre-flight verification probe on GA4 property."""
    print("🔍 [Pre-Flight] Verifying Google Analytics 4 (GA4) API access...")
    print(f"   Service Account: {client_email}")
    print(f"   GA4 Property ID: {property_id}")

    test_body = {
        "dateRanges": [{"startDate": "7daysAgo", "endDate": "today"}],
        "metrics": [{"name": "activeUsers"}]
    }

    res, status = run_ga4_report(token, property_id, test_body)
    if status == 200 and "rows" in res:
        total_users = res["rows"][0]["metricValues"][0]["value"] if res["rows"] else "0"
        print("✅ GA4 Data API Access Confirmed!")
        print(f"   Active Users (Last 7 Days): {total_users}\n")
        return True
    else:
        print(f"\n❌ GA4 API Verification Failed (HTTP {status})!")
        print(f"   Response: {res}")
        print("\n💡 ACTION REQUIRED:")
        print("   1. Open: https://analytics.google.com/")
        print("   2. Go to: Admin (gear icon) > Property access management")
        print(f"   3. Ensure email is added: {client_email} (Viewer role)")
        print(f"   4. Ensure Property ID is correct: {property_id}\n")
        return False


def display_pages_report(token: str, property_id: str, days: int, limit: int = 25):
    """Fetches and displays top page views and user engagement."""
    body = {
        "dateRanges": [{"startDate": f"{days}daysAgo", "endDate": "today"}],
        "dimensions": [{"name": "pagePath"}],
        "metrics": [
            {"name": "screenPageViews"},
            {"name": "activeUsers"},
            {"name": "userEngagementDuration"}
        ],
        "limit": limit
    }
    res, status = run_ga4_report(token, property_id, body)
    if status != 200 or not res.get("rows"):
        print(f"No pageview records found for past {days} days.")
        return

    print("=========================================================================================")
    print(f"📊 GA4 AUDIENCE & PAGEVIEWS (Past {days} Days)")
    print("=========================================================================================")
    print(f"{'Pageviews':>10} | {'Users':>6} | {'Avg Time':>9} | Page Path")
    print("-" * 75)

    rows = res.get("rows", [])
    total_views = sum(int(r["metricValues"][0]["value"]) for r in rows)
    total_users = sum(int(r["metricValues"][1]["value"]) for r in rows)

    for r in rows:
        path = r["dimensionValues"][0]["value"]
        views = int(r["metricValues"][0]["value"])
        users = int(r["metricValues"][1]["value"])
        duration = float(r["metricValues"][2]["value"])
        avg_time = f"{int(duration / max(1, users))}s" if users else "0s"

        print(f"{views:10,d} | {users:6,d} | {avg_time:>9} | {path}")

    print("-" * 75)
    print(f"{total_views:10,d} | {total_users:6,d} | {'--':>9} | TOTALS ({len(rows)} Pages)")
    print("=========================================================================================\n")


def display_events_report(token: str, property_id: str, days: int):
    """Fetches and displays custom actions and conversion events."""
    body = {
        "dateRanges": [{"startDate": f"{days}daysAgo", "endDate": "today"}],
        "dimensions": [{"name": "eventName"}],
        "metrics": [
            {"name": "eventCount"},
            {"name": "totalUsers"}
        ],
        "limit": 30
    }
    res, status = run_ga4_report(token, property_id, body)
    if status != 200 or not res.get("rows"):
        print("No custom event records found.")
        return

    print("=========================================================================================")
    print(f"🎯 GA4 ACTIONS & CONVERSIONS (Past {days} Days)")
    print("=========================================================================================")
    print(f"{'Event Count':>12} | {'Users':>6} | Event Name & Intent Category")
    print("-" * 70)

    rows = sorted(res.get("rows", []), key=lambda x: int(x["metricValues"][0]["value"]), reverse=True)
    for r in rows:
        name = r["dimensionValues"][0]["value"]
        cnt = int(r["metricValues"][0]["value"])
        users = int(r["metricValues"][1]["value"])

        # Tag intent
        tag = ""
        if "sign_success" in name:
            tag = "🏆 [CONVERSION: PDF Signed!]"
        elif "validator_success" in name:
            tag = "✅ [CONVERSION: PDF Validated!]"
        elif "sign_attempt" in name:
            tag = "⚡ [User Clicked Sign]"
        elif "tool_view" in name:
            tag = "🛠️ [Tool Studio Viewed]"
        elif "pdf_loaded" in name:
            tag = "📄 [File Selected]"
        elif "p12_loaded" in name:
            tag = "🔐 [Cert Loaded]"

        print(f"{cnt:12,d} | {users:6,d} | {name:<26} {tag}")
    print("=========================================================================================\n")


def display_sources_report(token: str, property_id: str, days: int):
    """Fetches traffic acquisition sources."""
    body = {
        "dateRanges": [{"startDate": f"{days}daysAgo", "endDate": "today"}],
        "dimensions": [{"name": "sessionSource"}, {"name": "sessionMedium"}],
        "metrics": [
            {"name": "activeUsers"},
            {"name": "sessions"}
        ],
        "limit": 15
    }
    res, status = run_ga4_report(token, property_id, body)
    if status != 200 or not res.get("rows"):
        return

    print("=========================================================================================")
    print(f"🌐 GA4 TRAFFIC SOURCES & ACQUISITION (Past {days} Days)")
    print("=========================================================================================")
    print(f"{'Users':>8} | {'Sessions':>9} | Source / Medium")
    print("-" * 60)
    for r in res.get("rows", []):
        src = r["dimensionValues"][0]["value"]
        med = r["dimensionValues"][1]["value"]
        users = int(r["metricValues"][0]["value"])
        sess = int(r["metricValues"][1]["value"])
        print(f"{users:8,d} | {sess:9,d} | {src} / {med}")
    print("=========================================================================================\n")


def display_devices_report(token: str, property_id: str, days: int):
    """Fetches device and operating system breakdown."""
    body = {
        "dateRanges": [{"startDate": f"{days}daysAgo", "endDate": "today"}],
        "dimensions": [{"name": "deviceCategory"}, {"name": "operatingSystem"}],
        "metrics": [
            {"name": "activeUsers"},
            {"name": "screenPageViews"}
        ],
        "limit": 15
    }
    res, status = run_ga4_report(token, property_id, body)
    if status != 200 or not res.get("rows"):
        return

    print("=========================================================================================")
    print(f"📱 GA4 DEVICE & OS DISTRIBUTION (Past {days} Days)")
    print("=========================================================================================")
    print(f"{'Users':>8} | {'Pageviews':>10} | Device Category (Operating System)")
    print("-" * 65)
    for r in res.get("rows", []):
        cat = r["dimensionValues"][0]["value"]
        os_name = r["dimensionValues"][1]["value"]
        users = int(r["metricValues"][0]["value"])
        views = int(r["metricValues"][1]["value"])
        print(f"{users:8,d} | {views:10,d} | {cat:<10} ({os_name})")
    print("=========================================================================================\n")


def main():
    parser = argparse.ArgumentParser(description="Google Analytics 4 Telemetry & Conversion Monitor")
    parser.add_argument("--property", type=str, default=DEFAULT_PROPERTY_ID, help="GA4 Property ID (numeric)")
    parser.add_argument("--creds", type=str, default=DEFAULT_CREDS_PATH, help="Path to Service Account JSON key")
    parser.add_argument("--days", type=int, default=28, help="Number of days to inspect (default: 28)")
    parser.add_argument("--pages", action="store_true", help="Display pageview metrics")
    parser.add_argument("--events", action="store_true", help="Display custom conversion events")
    parser.add_argument("--sources", action="store_true", help="Display traffic acquisition channels")
    parser.add_argument("--devices", action="store_true", help="Display device & OS distribution")
    parser.add_argument("--limit", type=int, default=25, help="Number of pages to display")
    parser.add_argument("--verify-only", action="store_true", help="Verify credentials and exit")

    args = parser.parse_args()

    # 1. Acquire Access Token
    token, err_or_email = get_ga4_access_token(args.creds)
    if not token:
        print(f"❌ Authentication Failed: {err_or_email}")
        sys.exit(1)

    client_email = err_or_email

    # 2. Pre-flight verification
    if not verify_ga4_setup(token, args.property, client_email):
        sys.exit(1)

    if args.verify_only:
        sys.exit(0)

    # 3. Render requested sections
    show_all = not (args.pages or args.events or args.sources or args.devices)

    if show_all or args.pages:
        display_pages_report(token, args.property, args.days, limit=args.limit)

    if show_all or args.events:
        display_events_report(token, args.property, args.days)

    if show_all or args.sources:
        display_sources_report(token, args.property, args.days)

    if show_all or args.devices:
        display_devices_report(token, args.property, args.days)


if __name__ == "__main__":
    main()
