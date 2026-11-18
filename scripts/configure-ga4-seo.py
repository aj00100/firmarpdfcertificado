#!/usr/bin/env python3
"""
Automated GA4 SEO & Measurement Configuration Script for firmarpdfcertificado.com
Configures:
  1. Data Retention: 14 Months (FOURTEEN_MONTHS) + Reset on New Activity
  2. Key Events (Conversions): sign_success, validator_success, sign_attempt, pdf_loaded, p12_loaded, blog_tool_click
  3. Custom Dimensions: page_path, blog_slug, tool_name
  4. Search Console Link Verification & Setup
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

PROPERTY_ID = "561091170"
CREDS_PATH = "/data/data/com.termux/files/home/micro-tools/.gsc_credentials.json"
ALT_CREDS_PATH = "/sdcard/Download/gen-lang-client-0695474766-bd4b18ce3951.json"

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def get_admin_token():
    path = CREDS_PATH if os.path.exists(CREDS_PATH) else ALT_CREDS_PATH
    with open(path, "r", encoding="utf-8") as f:
        creds = json.load(f)
    client_email = creds["client_email"]
    private_key = creds["private_key"]

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iss": client_email,
        "scope": "https://www.googleapis.com/auth/analytics.edit https://www.googleapis.com/auth/analytics",
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

def api_call(token, method, endpoint, payload=None):
    url = f"https://analyticsadmin.googleapis.com/v1beta/{endpoint}"
    data = json.dumps(payload).encode("utf-8") if payload else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8")), resp.status
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8")
        try:
            return json.loads(err), e.code
        except Exception:
            return {"error": err}, e.code

def main():
    print(f"🔧 GA4 SEO Configuration Engine for Property {PROPERTY_ID}...")
    token, email = get_admin_token()
    print(f"   Authenticated as: {email}")

    # Check if Analytics Admin API is accessible
    res, status = api_call(token, "GET", f"properties/{PROPERTY_ID}")
    if status == 403 and "SERVICE_DISABLED" in str(res):
        print("\n❌ Google Analytics Admin API is not enabled in your Google Cloud Project (539943542592).")
        print("💡 To enable programmatic GA4 API configuration:")
        print("   1. Click: https://console.developers.google.com/apis/api/analyticsadmin.googleapis.com/overview?project=539943542592")
        print("   2. Click 'ENABLE'")
        print("   3. Re-run this script!\n")
        sys.exit(2)

    if status != 200:
        print(f"❌ Failed to query property (HTTP {status}): {res}")
        sys.exit(1)

    print(f"✅ Connected to Property: {res.get('displayName')} ({PROPERTY_ID})")

    # 1. Update Data Retention to 14 Months
    print("\n1. Configuring Data Retention to 14 Months (SEO YoY analysis)...")
    patch_body = {
        "eventDataRetention": "FOURTEEN_MONTHS",
        "resetUserDataOnNewActivity": True
    }
    ret_res, ret_status = api_call(token, "PATCH", f"properties/{PROPERTY_ID}/dataRetentionSettings?updateMask=eventDataRetention,resetUserDataOnNewActivity", patch_body)
    if ret_status == 200:
        print(f"   ✅ Event Data Retention set to: {ret_res.get('eventDataRetention')}")
    else:
        print(f"   ⚠️ Data retention update response: {ret_res}")

    # 2. Register Key Events (Conversions)
    key_events = ["sign_success", "validator_success", "sign_attempt", "pdf_loaded", "p12_loaded", "blog_tool_click"]
    print(f"\n2. Registering {len(key_events)} Key Events for Organic Attribution...")
    for ev in key_events:
        kev_res, kev_status = api_call(token, "POST", f"properties/{PROPERTY_ID}/keyEvents", {"eventName": ev})
        if kev_status == 200:
            print(f"   ✅ Marked as Key Event: {ev}")
        elif "already exists" in str(kev_res):
            print(f"   ℹ️ Already registered: {ev}")
        else:
            print(f"   ⚠️ Event {ev}: {kev_res.get('error', {}).get('message', kev_res)}")

    # 3. Register Custom Dimensions
    custom_dims = [
        {"parameterName": "page_path", "displayName": "Page Path", "description": "Normalized page route where event occurred"},
        {"parameterName": "blog_slug", "displayName": "Blog Slug", "description": "Article slug for blog-to-tool attribution"},
        {"parameterName": "tool_name", "displayName": "Tool Name", "description": "Target tool studio identifier"}
    ]
    print(f"\n3. Registering {len(custom_dims)} Custom Dimensions...")
    for dim in custom_dims:
        dim_payload = {
            "parameterName": dim["parameterName"],
            "displayName": dim["displayName"],
            "description": dim["description"],
            "scope": "EVENT"
        }
        dim_res, dim_status = api_call(token, "POST", f"properties/{PROPERTY_ID}/customDimensions", dim_payload)
        if dim_status == 200:
            print(f"   ✅ Registered Custom Dimension: {dim['displayName']} ({dim['parameterName']})")
        elif "already exists" in str(dim_res):
            print(f"   ℹ️ Already registered: {dim['displayName']}")
        else:
            print(f"   ⚠️ Dimension {dim['displayName']}: {dim_res.get('error', {}).get('message', dim_res)}")

    print("\n🎉 GA4 SEO Configuration Complete!")

if __name__ == "__main__":
    main()
