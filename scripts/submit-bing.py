#!/usr/bin/env python3
"""
Automated Bing Webmaster URL & Sitemap Submission Script
Usage:
    python3 scripts/submit-bing.py [--quota] [--dry-run] [--force]
"""
import os
import re
import sys
import json
import argparse
import urllib.request
import urllib.error
from datetime import datetime

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

API_KEY = load_bing_key()
SITE_URL = 'https://firmarpdfcertificado.com'
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SITEMAP_FILE = os.path.join(SCRIPT_DIR, '..', 'dist', 'sitemap-0.xml')
CACHE_FILE = os.path.join(SCRIPT_DIR, '.bing_submitted_urls.json')

def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_cache(cache):
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        print(f"[WARN] Failed to write cache: {e}")

def check_quota():
    print("=== Bing Submission Quota ===")
    req = urllib.request.Request(
        f'https://ssl.bing.com/webmaster/api.svc/json/GetUrlSubmissionQuota?siteUrl={SITE_URL}&apikey={API_KEY}'
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            quota = data.get('d', {})
            daily = quota.get('DailyQuota')
            monthly = quota.get('MonthlyQuota')
            print(f"Daily Quota Remaining:   {daily}")
            print(f"Monthly Quota Remaining: {monthly}")
            return daily, monthly
    except Exception as e:
        print(f"[ERROR] Quota check failed: {e}")
        return None, None

def submit_sitemaps():
    feeds = [
        f'{SITE_URL}/sitemap-index.xml',
        f'{SITE_URL}/sitemap-0.xml'
    ]
    print("\n=== Submitting Sitemaps to Bing ===")
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

def submit_urls(force=False, dry_run=False):
    print("\n=== Submitting URLs to Bing ===")
    if not os.path.exists(SITEMAP_FILE):
        print(f"[ERROR] Sitemap file not found at {SITEMAP_FILE}. Run 'npm run build' first.")
        return

    with open(SITEMAP_FILE, 'r') as f:
        content = f.read()

    all_urls = re.findall(r'<loc>([^<]+)</loc>', content)
    cache = load_cache()

    if force:
        urls_to_submit = all_urls
        print(f"[FORCE] Submitting all {len(urls_to_submit)} URLs regardless of cache.")
    else:
        urls_to_submit = [u for u in all_urls if u not in cache]
        print(f"Discovered {len(all_urls)} total URLs in sitemap.")
        print(f"Found {len(cache)} previously submitted URLs in cache.")
        print(f"Strictly NEW URLs to submit: {len(urls_to_submit)}")

    if not urls_to_submit:
        print("[SKIP] All URLs have already been submitted! Quota preserved (0 credits burned).")
        return

    if dry_run:
        print(f"[DRY RUN] Would submit {len(urls_to_submit)} URLs:")
        for u in urls_to_submit:
            print(f"  - {u}")
        return

    payload = json.dumps({
        'siteUrl': SITE_URL,
        'urlList': urls_to_submit
    }).encode('utf-8')

    req = urllib.request.Request(
        f'https://ssl.bing.com/webmaster/api.svc/json/SubmitUrlbatch?apikey={API_KEY}',
        data=payload,
        headers={'Content-Type': 'application/json; charset=utf-8'}
    )

    try:
        with urllib.request.urlopen(req) as resp:
            print(f"[OK] SubmitUrlbatch successful (HTTP {resp.status}) - {len(urls_to_submit)} URLs submitted.")
            now_iso = datetime.utcnow().isoformat()
            for u in urls_to_submit:
                cache[u] = now_iso
            save_cache(cache)
    except urllib.error.HTTPError as e:
        print(f"[FAIL] SubmitUrlbatch: HTTP {e.code} - {e.read().decode()}")
    except Exception as e:
        print(f"[ERROR] SubmitUrlbatch: {e}")

def main():
    parser = argparse.ArgumentParser(description="Bing Webmaster URL Submission Guard")
    parser.add_argument('--quota', action='store_true', help='Only check quota without submitting')
    parser.add_argument('--dry-run', action='store_true', help='Simulate submission without burning quota')
    parser.add_argument('--force', action='store_true', help='Force resubmission of all URLs')
    parser.add_argument('--skip-sitemaps', action='store_true', help='Skip submitting sitemaps')
    args = parser.parse_args()

    if args.quota:
        check_quota()
        return

    check_quota()
    if not args.skip_sitemaps and not args.dry_run:
        submit_sitemaps()
    submit_urls(force=args.force, dry_run=args.dry_run)
    check_quota()

if __name__ == '__main__':
    main()
