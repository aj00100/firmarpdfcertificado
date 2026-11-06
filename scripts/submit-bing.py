#!/usr/bin/env python3
"""
Automated Bing Webmaster URL & Sitemap Submission Script
Usage: python3 scripts/submit-bing.py [API_KEY]
"""
import os
import re
import sys
import json
import urllib.request
import urllib.error

API_KEY = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('BING_API_KEY', '5975fcff074646aab15936d745241603')
SITE_URL = 'https://firmarpdfcertificado.com'
SITEMAP_FILE = os.path.join(os.path.dirname(__file__), '..', 'dist', 'sitemap-0.xml')

def submit_sitemaps():
    feeds = [
        f'{SITE_URL}/sitemap-index.xml',
        f'{SITE_URL}/sitemap-0.xml'
    ]
    print("=== Submitting Sitemaps to Bing ===")
    for feed in feeds:
        payload = json.dumps({'siteUrl': SITE_URL, 'feedUrl': feed}).encode('utf-8')
        req = urllib.request.Request(
            f'https://ssl.bing.com/webmaster/api.svc/json/SubmitFeed?apikey={API_KEY}',
            data=payload,
            headers={'Content-Type': 'application/json; charset=utf-8'}
        )
        try:
            with urllib.request.urlopen(req) as resp:
                print(f"[OK] SubmitFeed: {feed} (HTTP {resp.status})")
        except urllib.error.HTTPError as e:
            print(f"[FAIL] SubmitFeed {feed}: HTTP {e.code} - {e.read().decode()}")
        except Exception as e:
            print(f"[ERROR] SubmitFeed {feed}: {e}")

def submit_urls():
    print("\n=== Submitting URLs to Bing ===")
    if not os.path.exists(SITEMAP_FILE):
        print(f"[ERROR] Sitemap file not found at {SITEMAP_FILE}. Run 'npm run build' first.")
        return

    with open(SITEMAP_FILE, 'r') as f:
        content = f.read()

    urls = re.findall(r'<loc>([^<]+)</loc>', content)
    print(f"Discovered {len(urls)} URLs in {SITEMAP_FILE}")

    payload = json.dumps({
        'siteUrl': SITE_URL,
        'urlList': urls
    }).encode('utf-8')

    req = urllib.request.Request(
        f'https://ssl.bing.com/webmaster/api.svc/json/SubmitUrlbatch?apikey={API_KEY}',
        data=payload,
        headers={'Content-Type': 'application/json; charset=utf-8'}
    )

    try:
        with urllib.request.urlopen(req) as resp:
            print(f"[OK] SubmitUrlbatch successful (HTTP {resp.status})")
    except urllib.error.HTTPError as e:
        print(f"[FAIL] SubmitUrlbatch: HTTP {e.code} - {e.read().decode()}")
    except Exception as e:
        print(f"[ERROR] SubmitUrlbatch: {e}")

def check_quota():
    print("\n=== Checking Bing Submission Quota ===")
    req = urllib.request.Request(
        f'https://ssl.bing.com/webmaster/api.svc/json/GetUrlSubmissionQuota?siteUrl={SITE_URL}&apikey={API_KEY}'
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            quota = data.get('d', {})
            print(f"Daily Quota Remaining:   {quota.get('DailyQuota')}")
            print(f"Monthly Quota Remaining: {quota.get('MonthlyQuota')}")
    except Exception as e:
        print(f"[ERROR] Quota check failed: {e}")

if __name__ == '__main__':
    submit_sitemaps()
    submit_urls()
    check_quota()
