import os
import json
import re
import httpx
from src.core.utils import parse_date_to_iso

def parse_xml_feed(xml_text: str, source_name: str) -> list:
    """Safely parse RSS 2.0 or Atom XML feeds into standard dict list."""
    import xml.etree.ElementTree as ET

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
        for item in rss_items:
            title = item.find('title')
            link = item.find('link')
            desc = item.find('description')
            pub_date = item.find('pubDate')

            title_text = title.text if title is not None and title.text else ""
            link_text = link.text if link is not None and link.text else ""
            desc_text = desc.text if desc is not None and desc.text else ""
            pub_date_text = pub_date.text if pub_date is not None and pub_date.text else ""

            # Clean HTML from description
            desc_text = re.sub(r'<[^>]*>', '', desc_text).strip()
            if len(desc_text) > 280:
                desc_text = desc_text[:277] + "..."

            items.append({
                "title": title_text.strip(),
                "link": link_text.strip(),
                "description": desc_text,
                "pubDate": parse_date_to_iso(pub_date_text),
                "source": source_name
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
            desc_text = summary.text if summary is not None and summary.text else ""
            pub_date_text = pub_date.text if pub_date is not None and pub_date.text else ""

            # Clean HTML from description
            desc_text = re.sub(r'<[^>]*>', '', desc_text).strip()
            if len(desc_text) > 280:
                desc_text = desc_text[:277] + "..."

            items.append({
                "title": title_text.strip(),
                "link": link_text.strip(),
                "description": desc_text,
                "pubDate": parse_date_to_iso(pub_date_text),
                "source": source_name
            })

    return items

async def aggregate_security_feeds() -> list:
    """Fetch and combine real-time feeds from configured vulnerability databases."""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    feeds_path = os.path.join(base_dir, "config", "feeds.json")

    with open(feeds_path, "r", encoding="utf-8") as f:
        feeds = json.load(f)

    combined_feeds = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatDigestAgent/1.0"
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
    return combined_feeds
