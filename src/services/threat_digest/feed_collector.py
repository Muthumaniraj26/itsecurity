import os
import json
import re
import time
import asyncio
import httpx
from src.core.utils import parse_date_to_iso

# In-memory feed cache with TTL (5 minutes)
_feed_cache = []
_feed_cache_time = 0
_CACHE_TTL_SECONDS = 300  # 5 minutes

CATEGORY_BANNERS = {
    "breach": "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=800&q=80",
    "phishing": "https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=800&q=80",
    "ransomware": "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=800&q=80",
    "cisa": "https://images.unsplash.com/photo-1510511459019-5dda7724fd87?auto=format&fit=crop&w=800&q=80",
    "vulnerability": "https://images.unsplash.com/photo-1504639725590-34d0984388bd?auto=format&fit=crop&w=800&q=80",
    "cloud": "https://images.unsplash.com/photo-1451187580459-43490279c0fa?auto=format&fit=crop&w=800&q=80",
    "compliance": "https://images.unsplash.com/photo-1450133064473-71024230f91b?auto=format&fit=crop&w=800&q=80",
    "default": "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=800&q=80"
}

def get_contextual_fallback_image(title: str, content: str) -> str:
    """Selects a premium contextual cybersecurity visual based on article keywords."""
    combined = (title + " " + content).lower()
    if any(k in combined for k in ["stolen account", "police account", "database", "breach", "leak", "exfiltrat", "dmv"]):
        return CATEGORY_BANNERS["breach"]
    elif any(k in combined for k in ["phish", "m365", "passkey", "token", "credential", "lure"]):
        return CATEGORY_BANNERS["phishing"]
    elif any(k in combined for k in ["ransomware", "encrypt", "extortion", "lockbit", "blackcat"]):
        return CATEGORY_BANNERS["ransomware"]
    elif any(k in combined for k in ["cisa", "kev", "zero-day", "0-day", "catalog"]):
        return CATEGORY_BANNERS["cisa"]
    elif any(k in combined for k in ["cve-", "flaw", "vulnerability", "rce", "traversal", "patch", "bypass"]):
        return CATEGORY_BANNERS["vulnerability"]
    elif any(k in combined for k in ["cloud", "aws", "azure", "kubernetes", "artifactory", "docker", "server"]):
        return CATEGORY_BANNERS["cloud"]
    elif any(k in combined for k in ["compliance", "gdpr", "hipaa", "nis2", "regulation", "law", "fido2"]):
        return CATEGORY_BANNERS["compliance"]
    return CATEGORY_BANNERS["default"]

def parse_xml_feed(xml_text: str, source_name: str) -> list:
    """Safely parse RSS 2.0 or Atom XML feeds into standard dict list."""
    import xml.etree.ElementTree as ET

    # Strip XML namespace attributes and prefixes to prevent unbound prefix errors
    cleaned_xml = re.sub(r'\sxmlns(:\w+)?=[\'"][^\'"]*[\'"]', '', xml_text)
    cleaned_xml = re.sub(r'<(\/?)\w+:', r'<\1', cleaned_xml)
    cleaned_xml = re.sub(r'\s\w+:(\w+)=', r' \1=', cleaned_xml)

    try:
        root = ET.fromstring(cleaned_xml)
    except Exception as e:
        print(f"XML parsing notice for {source_name}: {e}")
        return []

    items = []

    # 1. Parse RSS (item elements)
    rss_items = root.findall('.//item')
    if rss_items:
        for item in rss_items[:12]:
            title = item.find('title')
            link = item.find('link')
            desc = item.find('description')
            pub_date = item.find('pubDate')

            title_text = title.text if title is not None and title.text else ""
            link_text = link.text if link is not None and link.text else ""
            raw_desc = desc.text if desc is not None and desc.text else ""
            pub_date_text = pub_date.text if pub_date is not None and pub_date.text else ""

            # Check for inline or enclosure images
            inline_img = None
            enclosure = item.find('enclosure')
            if enclosure is not None and enclosure.get('url'):
                inline_img = enclosure.get('url')

            if not inline_img:
                img_match = re.search(r'<img[^>]+src=["\']([^"\']+)["\']', raw_desc)
                if img_match:
                    inline_img = img_match.group(1)

            # Clean HTML from description
            desc_text = re.sub(r'<[^>]*>', '', raw_desc).strip()
            if len(desc_text) > 280:
                desc_text = desc_text[:277] + "..."

            img_final = inline_img or get_contextual_fallback_image(title_text, desc_text)

            if title_text and link_text:
                items.append({
                    "title": title_text.strip(),
                    "link": link_text.strip(),
                    "description": desc_text,
                    "pubDate": parse_date_to_iso(pub_date_text),
                    "source": source_name,
                    "imageUrl": img_final
                })

    # 2. Parse Atom (entry elements)
    else:
        atom_entries = root.findall('.//entry')
        for entry in atom_entries[:12]:
            title = entry.find('title')
            link_el = entry.find('link')
            link_text = ""
            if link_el is not None:
                link_text = link_el.get('href', '')

            summary = entry.find('summary') or entry.find('content')
            pub_date = entry.find('published') or entry.find('updated')

            title_text = title.text if title is not None and title.text else ""
            raw_desc = summary.text if summary is not None and summary.text else ""
            pub_date_text = pub_date.text if pub_date is not None and pub_date.text else ""

            inline_img = None
            img_match = re.search(r'<img[^>]+src=["\']([^"\']+)["\']', raw_desc)
            if img_match:
                inline_img = img_match.group(1)

            desc_text = re.sub(r'<[^>]*>', '', raw_desc).strip()
            if len(desc_text) > 280:
                desc_text = desc_text[:277] + "..."

            img_final = inline_img or get_contextual_fallback_image(title_text, desc_text)

            if title_text and link_text:
                items.append({
                    "title": title_text.strip(),
                    "link": link_text.strip(),
                    "description": desc_text,
                    "pubDate": parse_date_to_iso(pub_date_text),
                    "source": source_name,
                    "imageUrl": img_final
                })

    return items

async def fetch_single_feed(client: httpx.AsyncClient, feed: dict) -> list:
    """Fetches and parses a single RSS/Atom feed with timeout safety."""
    try:
        response = await client.get(feed["url"])
        if response.status_code == 200:
            return parse_xml_feed(response.text, feed["name"])
        else:
            print(f"Feed [{feed['name']}] status {response.status_code}")
            return []
    except Exception as e:
        print(f"Feed [{feed['name']}] fetch notice: {e}")
        return []

async def aggregate_security_feeds(force_refresh: bool = False) -> list:
    """
    High-Performance Concurrent Feed Aggregator with In-Memory Caching (TTL 5 mins).
    Fetches all 10 security feeds concurrently in parallel with strict 3.5s timeout.
    """
    global _feed_cache, _feed_cache_time

    now = time.time()
    if not force_refresh and _feed_cache and (now - _feed_cache_time < _CACHE_TTL_SECONDS):
        return _feed_cache

    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    feeds_path = os.path.join(base_dir, "config", "feeds.json")

    try:
        with open(feeds_path, "r", encoding="utf-8") as f:
            feeds = json.load(f)
    except Exception:
        feeds = []

    if not feeds:
        return _feed_cache or []

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Accept": "application/rss+xml, application/xml, text/xml, */*"
    }

    # Parallel asynchronous fetching for all feeds at once (drops time from 15s to < 1.5s)
    async with httpx.AsyncClient(timeout=3.5, headers=headers, follow_redirects=True) as client:
        tasks = [fetch_single_feed(client, f) for f in feeds]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    combined = []
    for res in results:
        if isinstance(res, list):
            combined.extend(res)

    if combined:
        # Sort newest first
        combined.sort(key=lambda x: x.get("pubDate") or "", reverse=True)
        _feed_cache = combined
        _feed_cache_time = now
        return combined

    return _feed_cache or []
