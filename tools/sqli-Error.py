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
SQLi_PAYLOADS = [
    "'",
    '"',
    '`',
    "')",
    '")',
    '`)',
    "'))",
    '"))',
    '`))',
    '%'
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


async def inject_SQLi_payload(session, request, semaphore):
    """
    Inject SQLi payloads into GET params, POST bodies, and paths while avoiding Content-Length mismatches.
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
                for payload in SQLi_PAYLOADS:
                    modified_params = query_params.copy()
                    modified_params[param] = [payload for _ in values]
                    new_query_string = "&".join(
                        f"{p}={v}" for p, vals in modified_params.items() for v in vals
                    )
                    # Build new URL preserving scheme/netloc and path
                    new_url = parsed_url._replace(query=new_query_string).geturl()

                    # Let test_SQLi clean headers centrally; pass a copy
                    result = await test_SQLi(session, new_url, method, headers=headers.copy())
                    if result and result["SQLi_detected"]:
                        result["query_params"] = query_params
                        result["modified_query_params"] = modified_params
                        result["payload"] = payload
                        results.append(result)
                        break

        # --- 2. POST requests with body payloads ---
        elif method == "POST" and body is not None:
            for payload in SQLi_PAYLOADS:
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

                # Pass copies of headers -- test_SQLi will clean them
                try:
                    result = await test_SQLi(session, url, method, headers=headers.copy(), data=data_to_send, json_data=json_to_send)
                    if result and result["SQLi_detected"]:
                        result["post_data"] = body
                        result["modified_post_data"] = (json_to_send if json_to_send is not None else data_to_send)
                        result["payload"] = payload
                        results.append(result)
                        break
                except Exception as e:
                    logging.error(f"Error while testing SQLi payload (POST) on {url}: {e}")
                    continue

        # --- 3. Path-based SQLi injection ---
        if method in ("GET", "POST"):
            # split path and preserve empty root handling
            path = parsed_url.path or "/"
            stripped = path.strip("/")
            path_parts = stripped.split("/") if stripped != "" else []
            # if there are no parts (root), we can still try injecting after root by adding parts
            indices = range(len(path_parts))
            for i, part in enumerate(path_parts):
                if part == "":
                    continue
                for payload in SQLi_PAYLOADS:
                    modified_parts = path_parts.copy()
                    modified_parts[i] = part + payload
                    modified_path = "/" + "/".join(modified_parts)
                    new_url = parsed_url._replace(path=modified_path).geturl()

                    try:
                        result = await test_SQLi(session, new_url, method, headers=headers.copy())
                        if result and result["SQLi_detected"]:
                            result["path"] = parsed_url.path
                            result["modified_path"] = modified_path
                            result["payload"] = payload
                            results.append(result)
                            break
                    except Exception as e:
                        logging.error(f"Error while testing path-based SQLi payload on {new_url}: {e}")
    return results


async def test_SQLi(session, url, method, headers=None, data=None, json_data=None):
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
        if re.search(r'- unterminated quoted string at or near|SQL syntax.*?MySQL|Warning.*?mysql_.*|Warning.*?\Wmysqli?_|MySQL Query fail.*|valid MySQL result|SQL syntax.*MariaDB server|.ou\s+.*SQL\s+syntax.*|.atabase\s*Query\s*Failed.*|MySqlException \(0x|valid MySQL result|check the manual that (corresponds to|fits) your (MySQL|MariaDB|Drizzle) server version|MySqlClient\.|com\.mysql\.jdbc|Zend_Db_(Adapter|Statement)_Mysqli_Exception|SQLSTATE\[\d+\]: Syntax error or access violation|MemSQL does not support this type of query|is not supported by MemSQL|unsupported nested scalar subselect|MySqlException|valid MySQL result|Pdo[./_\\]Mysql|Unknown column \'[^ ]+\' in \'field list\'|A Database error Occurred|PostgreSQL.*ERROR|Warning.*\Wpg_.*|Warning.*PostgreSQL|valid PostgreSQL result|Npgsql\.|PG::SyntaxError:|org\.postgresql\.util\.PSQLException|ERROR:\s+syntax error at or near |ERROR: parser: parse error at or near|PostgreSQL query failed|org\.postgresql\.jdbc|Pdo[./_\\]Pgsql|PSQLException|Driver.* SQL[\-\_\ ]*Server|OLE DB.* SQL Server|(\W|\A)SQL Server.*Driver|Warning.*odbc_.*|\bSQL Server[^&lt;&quot;]+Driver|Warning.*mssql_|Warning.*?\W(mssql|sqlsrv)_|Msg \d+, Level \d+, State \d+|Unclosed quotation mark after the character string|Microsoft OLE DB Provider for ODBC Drivers|Warning.*(mssql|sqlsrv)_|\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}|System\.Data\.SqlClient\.SqlException|Exception.*\WRoadhouse\.Cms\.|Microsoft SQL Native Client error \'[0-9a-fA-F]{8}|com\.microsoft\.sqlserver\.jdbc\.SQLServerException|\[SQL Server\]|ODBC SQL Server Driver|ODBC Driver \d+ for SQL Server|SQLServer JDBC Driver|macromedia\.jdbc\.sqlserver|com\.jnetdirect\.jsql|.*icrosoft\s+VBScript\s+runtime\s+error\s+.*|Zend_Db_(Adapter|Statement)_Sqlsrv_Exception|Pdo[./_\\](Mssql|SqlSrv)|SQL(Srv|Server)Exception|Microsoft SQL (?:Server\s)?Native Client (?:[\d\.]+ )?error [0-9a-fA-F]{8}|Microsoft Access Driver|Access Database Engine|Microsoft JET Database Engine|.*Syntax error.*query expression|\bORA-\d{4}|Oracle error|Warning.*oci_.*|CLI Driver.*DB2|DB2 SQL error|SQLite/JDBCDriver|System\.Data\.SQLite\.SQLiteException|Warning.*ibase_.*|com\.informix\.jdbc|Warning.*sybase.*|Sybase message|Incorrect syntax near', response.text):
            return {
                "url": url,
                "method": method,
                "status_code": response.status_code,
                "SQLi_detected": True,
                "response_excerpt": response.text[:1000]  # small excerpt for debugging
            }
        return {
            "url": url,
            "method": method,
            "status_code": response.status_code,
            "SQLi_detected": False
        }
    except httpx.RequestError as e:
        logging.error(f"HTTP error testing {url}: {e}")
        return {
            "url": url,
            "method": method,
            "status_code": "Error",
            "SQLi_detected": False,
            "error": str(e)
        }
    except Exception as e:
        logging.error(f"Unexpected error testing {url}: {e}")
        return {
            "url": url,
            "method": method,
            "status_code": "Error",
            "SQLi_detected": False,
            "error": str(e)
        }


async def process_requests(requests):
    """
    Process all requests and check for SQLi vulnerabilities.
    """
    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)
    async with httpx.AsyncClient() as session:
        tasks = [inject_SQLi_payload(session, request, semaphore) for request in requests]
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
    SQLi_results = [result for result in results if result.get("SQLi_detected")]
    if not SQLi_results:
        print(Fore.YELLOW + "No SQLi vulnerabilities detected.")
        return

    table_data = []
    for result in SQLi_results:
        table_data.append([
            result.get("url"),
            result.get("method"),
            result.get("status_code"),
            Fore.RED + "SQLi Detected"
        ])
    headers = ["URL", "Method", "Status Code", "SQLi Detection"]
    print(tabulate(table_data, headers, tablefmt="grid", stralign="center"))


async def main(input_file, output_file):
    global last_results
    requests = load_requests(input_file)
    logging.info(f"Loaded {len(requests)} requests for testing.")

    results = await process_requests(requests)
    # Filter results to only include SQLi detections
    SQLi_results = [result for result in results if result.get("SQLi_detected")]
    last_results = SQLi_results  # keep for SIGINT save

    print_results(SQLi_results)
    save_results(SQLi_results, output_file)


if __name__ == "__main__":
    parser = argparse = __import__("argparse").ArgumentParser(description="SQLi Detection Tool")
    parser.add_argument("--input", default="requests.json", help="Input file with requests")
    parser.add_argument("--output", default="SQLi_Error.json", help="Output file for results")
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

