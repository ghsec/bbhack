import argparse
import json
import re
import time

def parse_fetch_log(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = re.compile(
        r'fetch\((["\'])(?P<url>.*?)\1\s*,\s*(?P<config>\{.*?\})\s*\);',
        re.DOTALL
    )

    results = []
    seen = set()  # To track duplicates (url, method, body)

    for match in pattern.finditer(content):
        url = match.group("url")
        config_str = match.group("config")

        try:
            config_str_fixed = re.sub(r',(\s*})', r'\1', config_str)
            config_str_fixed = config_str_fixed.replace("'", '"')
            config = json.loads(config_str_fixed)
        except json.JSONDecodeError as e:
            print(f"Warning: JSON decode failed for fetch config at {url}: {e}")
            continue

        method = config.get("method", "GET")
        headers = config.get("headers", {})
        body = config.get("body", None)

        # Create deduplication key
        key = (url, method, body)

        if key in seen:
            continue  # skip duplicates
        seen.add(key)

        entry = {
            "url": url,
            "method": method,
            "status_code": None,
            "headers": headers,
            "response_headers": {},
            "body": body,
            "parent_url": None,
            "timestamp": time.time()
        }
        results.append(entry)

    return results

def main():
    parser = argparse.ArgumentParser(description="Parse fetch() calls log and save as JSON")
    parser.add_argument("-f", "--file", required=True, help="Path to fetch calls log file")
    parser.add_argument("-o", "--output", required=True, help="Path to output JSON file")

    args = parser.parse_args()

    parsed = parse_fetch_log(args.file)

    with open(args.output, "w", encoding="utf-8") as out_f:
        json.dump(parsed, out_f, indent=2, ensure_ascii=False)

    print(f"[+] Parsed {len(parsed)} unique fetch calls and saved to {args.output}")

if __name__ == "__main__":
    main()

