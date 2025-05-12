import argparse
import xml.etree.ElementTree as ET
import base64
import json
import time

def parse_burp_xml(file_path, parent_url=""):
    tree = ET.parse(file_path)
    root = tree.getroot()
    requests_data = []

    for item in root.findall("item"):
        url = item.findtext("url")
        request_raw = item.findtext("request")
        response_raw = item.findtext("response")

        method = "GET"
        status_code = None
        headers = {}
        response_headers = {}
        body = None

        # Decode request
        try:
            decoded_request = base64.b64decode(request_raw).decode("utf-8", errors="replace")
            lines = decoded_request.split("\r\n")
            if lines:
                method = lines[0].split()[0]
            headers = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
            body_index = len(headers) + 2
            body = "\n".join(lines[body_index:]) if body_index < len(lines) else None
        except Exception as e:
            print(f"⚠️ Failed to parse request for {url}: {e}")

        # Decode response
        try:
            decoded_response = base64.b64decode(response_raw).decode("utf-8", errors="replace")
            lines = decoded_response.split("\r\n")
            if lines:
                status_code = int(lines[0].split()[1])
                response_headers = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
        except Exception as e:
            print(f"⚠️ Failed to parse response for {url}: {e}")

        requests_data.append({
            "url": url,
            "method": method,
            "status_code": status_code,
            "headers": headers,
            "response_headers": response_headers,
            "body": body,
            "parent_url": parent_url,
            "timestamp": time.time(),
        })

    return requests_data

def main():
    parser = argparse.ArgumentParser(description="Convert Burp Suite XML to JSON with request-like structure.")
    parser.add_argument("-f", "--file", required=True, help="Path to Burp Suite XML file")
    parser.add_argument("-o", "--output", default="burp_items.json", help="Output JSON filename")
    parser.add_argument("--parent-url", default="", help="Optional parent URL to include in output")
    args = parser.parse_args()

    data = parse_burp_xml(args.file, args.parent_url)

    with open(args.output, "w", encoding="utf-8") as out_file:
        json.dump(data, out_file, indent=2, ensure_ascii=False)

    print(f"✅ Converted {len(data)} items to {args.output}")

if __name__ == "__main__":
    main()

