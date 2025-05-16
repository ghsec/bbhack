import sys
import json
import re
from urllib.parse import urlparse

def extract_json_object(text):
    match = re.search(r'fetch\((["\'])(.*?)\1,\s*(\{.*\})\s*\)', text, re.DOTALL)
    if not match:
        raise ValueError("Could not parse fetch() structure.")
    url = match.group(2)
    options_json = match.group(3)

    # Fix for JavaScript-style JSON (e.g. true/false instead of True/False)
    options_json = options_json.replace("true", "True").replace("false", "False").replace("null", "None")

    # Convert to valid Python dict
    options = eval(options_json)

    method = options.get("method", "GET").upper()
    headers = options.get("headers", {})
    body = options.get("body", "")

    return url, method, headers, body

def build_raw_http(url, method, headers, body):
    parsed = urlparse(url)
    path = parsed.path + ("?" + parsed.query if parsed.query else "")
    raw = f"{method} {path} HTTP/1.1\n"
    raw += f"Host: {parsed.netloc}\n"
    for k, v in headers.items():
        raw += f"{k}: {v}\n"
    if body:
        raw += f"Content-Length: {len(body.encode('utf-8'))}\n"
    raw += "\n"
    raw += body + "\n" if body else ""
    return raw

# === MAIN ===

if len(sys.argv) != 2:
    print("Usage: python fetch_to_raw.py <fetch_file.txt>")
    sys.exit(1)

with open(sys.argv[1], 'r') as f:
    fetch_code = f.read()

try:
    url, method, headers, body = extract_json_object(fetch_code)
    raw_request = build_raw_http(url, method, headers, body)
    print("=== RAW HTTP REQUEST ===")
    print(raw_request)
except Exception as e:
    print(f"Error: {e}")

