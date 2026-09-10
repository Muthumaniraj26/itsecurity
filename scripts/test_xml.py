import httpx
import re
import xml.etree.ElementTree as ET

async def test_xml():
    import json
    with open("config/feeds.json", "r") as f:
        feeds = json.load(f)
        
    for feed in feeds:
        print(f"\nFetching {feed['name']}...")
        try:
            async with httpx.AsyncClient() as client:
                res = await client.get(feed['url'])
                xml_text = res.text
            
            # Apply sanitization
            xml_text_sanitized = re.sub(r'\sxmlns(:\w+)?=[\'"][^\'"]*[\'"]', '', xml_text)
            xml_text_sanitized = re.sub(r'<(\/?)\w+:', r'<\1', xml_text_sanitized)
            xml_text_sanitized = re.sub(r'\s\w+:(\w+)=', r' \1=', xml_text_sanitized)

            root = ET.fromstring(xml_text_sanitized)
            print(f"Success! {feed['name']} parsed root: {root.tag}")
        except Exception as e:
            print(f"Failed to parse {feed['name']}: {e}")
            # Search for line number
            match = re.search(r'line (\d+)', str(e))
            if match:
                line_num = int(match.group(1))
                lines = xml_text_sanitized.split('\n')
                start = max(0, line_num - 5)
                end = min(len(lines), line_num + 5)
                print(f"Lines around error (line {line_num}):")
                for idx in range(start, end):
                    marker = "-->" if idx == line_num - 1 else "   "
                    print(f"{marker} {idx+1}: {lines[idx]}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_xml())
