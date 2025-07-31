import argparse
import base64
import json
import time
import xml.etree.ElementTree as ET

def parse_burp_log(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    entries = []

    for item in root.findall(".//item"):
        request_el = item.find("request")
        response_el = item.find("response")
        url = item.findtext("url")
        method = item.findtext("method")
        status_code = int(item.findtext("status")) if item.find("status") is not None else None

        # Decode base64 request and response
        request_raw = base64.b64decode(request_el.text).decode("utf-8", errors="replace") if request_el is not None else ""
        response_raw = base64.b64decode(response_el.text).decode("utf-8", errors="replace") if response_el is not None else ""

        # Extract request headers and body
        request_lines = request_raw.split("\r\n")
        headers = {}
        body = None
        for line in request_lines[1:]:
            if line == "":
                break
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key] = value
        if "\r\n\r\n" in request_raw:
            body = request_raw.split("\r\n\r\n", 1)[1]

        # Extract response headers
        response_headers = {}
        if response_raw:
            parts = response_raw.split("\r\n\r\n", 1)
            if len(parts) > 0:
                for line in parts[0].split("\r\n")[1:]:
                    if ": " in line:
                        key, value = line.split(": ", 1)
                        response_headers[key] = value

        entry = {
            "url": url,
            "method": method,
            "status_code": status_code,
            "headers": headers,
            "response_headers": response_headers,
            "body": body if body else None,
            "parent_url": None,
            "timestamp": time.time()
        }

        entries.append(entry)

    return entries

def main():
    parser = argparse.ArgumentParser(description="Parse Burp log and extract simplified request data.")
    parser.add_argument("-f", "--file", required=True, help="Path to Burp XML log file")
    parser.add_argument("-o", "--output", required=True, help="Path to output JSON file")

    args = parser.parse_args()

    parsed_data = parse_burp_log(args.file)

    with open(args.output, "w", encoding="utf-8") as out_file:
        json.dump(parsed_data, out_file, indent=2, ensure_ascii=False)

    print(f"[+] Parsed {len(parsed_data)} entries and saved to {args.output}")

if __name__ == "__main__":
    main()
