import os
import json
import re
import asyncio
import httpx
from src.core.utils import parse_date_to_iso

# In-memory image cache to ensure fast responses
_image_cache = {}

# High-resolution, professional cybersecurity banner images for topic fallbacks
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

    # Extract enclosure / media tags before stripping namespaces
    raw_img_urls = re.findall(r'<enclosure[^>]+url=["\']([^"\']+\.(?:jpg|png|webp|jpeg)[^"\']*)["\']', xml_text, re.IGNORECASE)

    # Strip XML namespace attributes and prefixes to prevent unbound prefix errors
    xml_text = re.sub(r'\sxmlns(:\w+)?=[\'"][^\'"]*[\'"]', '', xml_text)
    xml_text = re.sub(r'<(\/?)\w+:', r'<\1', xml_text)
    xml_text = re.sub(r'\s\w+:(\w+)=', r' \1=', xml_text)

    try:
        root = ET.fromstring(xml_text)
    except Exception as e:
        print(f"XML parsing failed for {source_name}: {e}")
        return []

    items = []

    # 1. Parse RSS (item elements)
    rss_items = root.findall('.//item')
    if rss_items:
        for idx, item in enumerate(rss_items):
            title = item.find('title')
            link = item.find('link')
            desc = item.find('description')
            pub_date = item.find('pubDate')

            title_text = title.text if title is not None and title.text else ""
            link_text = link.text if link is not None and link.text else ""
            raw_desc = desc.text if desc is not None and desc.text else ""
            pub_date_text = pub_date.text if pub_date is not None and pub_date.text else ""

            # Check for inline img src in description
            inline_img = None
            img_match = re.search(r'<img[^>]+src=["\']([^"\']+)["\']', raw_desc)
            if img_match:
                inline_img = img_match.group(1)

            # Clean HTML from description
            desc_text = re.sub(r'<[^>]*>', '', raw_desc).strip()
            if len(desc_text) > 280:
                desc_text = desc_text[:277] + "..."

            items.append({
                "title": title_text.strip(),
                "link": link_text.strip(),
                "description": desc_text,
                "pubDate": parse_date_to_iso(pub_date_text),
                "source": source_name,
                "imageUrl": inline_img
            })

    # 2. Parse Atom (entry elements)
    else:
        atom_entries = root.findall('.//entry')
        for entry in atom_entries:
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

            items.append({
                "title": title_text.strip(),
                "link": link_text.strip(),
                "description": desc_text,
                "pubDate": parse_date_to_iso(pub_date_text),
                "source": source_name,
                "imageUrl": inline_img
            })

    return items

async def fetch_article_og_image(client: httpx.AsyncClient, link: str) -> str:
    """Fetch OpenGraph image from article webpage with in-memory caching."""
    if not link or not link.startswith("http"):
        return None
    if link in _image_cache:
        return _image_cache[link]

    try:
        r = await client.get(link, timeout=2.5, follow_redirects=True)
        if r.status_code == 200:
            og_img = re.search(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', r.text)
            if not og_img:
                og_img = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:image["\']', r.text)
            if og_img:
                img_url = og_img.group(1).strip()
                _image_cache[link] = img_url
                return img_url
    except Exception:
        pass
    return None

async def enrich_feed_images(items: list) -> list:
    """Enrich all feed items with real article images or contextual cyber visuals."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    }
    
    async with httpx.AsyncClient(headers=headers, timeout=3.0) as client:
        tasks = []
        for item in items:
            if not item.get("imageUrl") and "bleepingcomputer.com" in item.get("link", ""):
                tasks.append(fetch_article_og_image(client, item["link"]))
            else:
                tasks.append(asyncio.sleep(0, result=item.get("imageUrl")))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for item, res in zip(items, results):
            if isinstance(res, str) and res.startswith("http"):
                item["imageUrl"] = res
            elif not item.get("imageUrl"):
                item["imageUrl"] = get_contextual_fallback_image(item.get("title", ""), item.get("description", ""))

    return items

async def aggregate_security_feeds() -> list:
    """Fetch and combine real-time feeds from configured vulnerability databases with image enrichment."""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    feeds_path = os.path.join(base_dir, "config", "feeds.json")

    with open(feeds_path, "r", encoding="utf-8") as f:
        feeds = json.load(f)

    combined_feeds = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    }

    async with httpx.AsyncClient(timeout=7.0, headers=headers) as client:
        for feed in feeds:
            try:
                response = await client.get(feed["url"])
                if response.status_code == 200:
                    feed_items = parse_xml_feed(response.text, feed["name"])
                    combined_feeds.extend(feed_items[:8])
                else:
                    print(f"Failed to fetch {feed['name']} Status code: {response.status_code}")
            except Exception as e:
                print(f"Network error loading feed {feed['name']}: {e}")

    combined_feeds.sort(key=lambda x: x["pubDate"], reverse=True)
    enriched_feeds = await enrich_feed_images(combined_feeds)
    return enriched_feeds
