import json
import logging
import asyncio
import httpx
import re
from urllib.parse import urlparse, urljoin, urlencode, parse_qs
from tabulate import tabulate
from colorama import init, Fore

# Initialize colorama for colored output
init(autoreset=True)

# Configuration
SQLI_PAYLOADS = [
    "'",
    '"',
    '`',
    "')",
    '")',
    '`)',
    "'))",
    '"))',
    '`))',
]

pattern = re.compile(
    r"- unterminated quoted string at or near"
    r"|SQL syntax.*?MySQL"
    r"|Warning.*?mysql_.*"
    r"|Warning.*?\Wmysqli?_"
    r"|MySQL Query fail.*"
    r"|valid MySQL result"
    r"|SQL syntax.*MariaDB server"
    r"|.ou\s+.*SQL\s+syntax.*"
    r"|.atabase\s*Query\s*Failed.*"
    r"|MySqlException \(0x"
    r"|valid MySQL result"
    r"|check the manual that (corresponds to|fits) your (MySQL|MariaDB|Drizzle) server version"
    r"|MySqlClient\."
    r"|com\.mysql\.jdbc"
    r"|Zend_Db_(Adapter|Statement)_Mysqli_Exception"
    r"|SQLSTATE\[\d+\]: Syntax error or access violation"
    r"|MemSQL does not support this type of query"
    r"|is not supported by MemSQL"
    r"|unsupported nested scalar subselect"
    r"|MySqlException"
    r"|valid MySQL result"
    r"|Pdo[./_\\]Mysql"
    r"|Unknown column '[^ ]+' in 'field list'"
    r"|A Database error Occurred"
    r"|PostgreSQL.*ERROR"
    r"|Warning.*\Wpg_.*"
    r"|Warning.*PostgreSQL"
    r"|valid PostgreSQL result"
    r"|Npgsql\."
    r"|PG::SyntaxError:"
    r"|org\.postgresql\.util\.PSQLException"
    r"|ERROR:\s+syntax error at or near "
    r"|ERROR: parser: parse error at or near"
    r"|PostgreSQL query failed"
    r"|org\.postgresql\.jdbc"
    r"|Pdo[./_\\]Pgsql"
    r"|PSQLException"
    r"|Driver.* SQL[\-\_\ ]*Server"
    r"|OLE DB.* SQL Server"
    r"|(\W|\A)SQL Server.*Driver"
    r"|Warning.*odbc_.*"
    r"|\bSQL Server[^&lt;&quot;]+Driver"
    r"|Warning.*mssql_"
    r"|Warning.*?\W(mssql|sqlsrv)_"
    r"|Msg \d+, Level \d+, State \d+"
    r"|Unclosed quotation mark after the character string"
    r"|Microsoft OLE DB Provider for ODBC Drivers"
    r"|Warning.*(mssql|sqlsrv)_"
    r"|\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}"
    r"|System\.Data\.SqlClient\.SqlException"
    r"|Exception.*\WRoadhouse\.Cms\."
    r"|Microsoft SQL Native Client error '[0-9a-fA-F]{8}"
    r"|com\.microsoft\.sqlserver\.jdbc\.SQLServerException"
    r"|\[SQL Server\]"
    r"|ODBC SQL Server Driver"
    r"|ODBC Driver \d+ for SQL Server"
    r"|SQLServer JDBC Driver"
    r"|macromedia\.jdbc\.sqlserver"
    r"|com\.jnetdirect\.jsql"
    r"|.*icrosoft\s+VBScript\s+runtime\s+error\s+.*"
    r"|Zend_Db_(Adapter|Statement)_Sqlsrv_Exception"
    r"|Pdo[./_\\](Mssql|SqlSrv)"
    r"|SQL(Srv|Server)Exception"
    r"|Microsoft SQL (?:Server\s)?Native Client (?:[\d\.]+ )?error '[0-9a-fA-F]{8}"
    r"|Microsoft Access Driver"
    r"|Access Database Engine"
    r"|Microsoft JET Database Engine"
    r"|.*Syntax error.*query expression"
    r"|\bORA-\d{4}"
    r"|Oracle error"
    r"|Warning.*oci_.*"
    r"|CLI Driver.*DB2"
    r"|DB2 SQL error"
    r"|SQLite/JDBCDriver"
    r"|System\.Data\.SQLite\.SQLiteException"
    r"|Warning.*ibase_.*"
    r"|com\.informix\.jdbc"
    r"|Warning.*sybase.*"
    r"|Sybase message"
)


DEFAULT_TIMEOUT = 50

# Concurrency limit for async tasks
SEMAPHORE_LIMIT = 5  # You can adjust this value based on your system's capacity

async def inject_SQLI_payload(session, request, semaphore):
    """
    Inject SQLI payloads into the request and test for vulnerabilities, including path-based SQLI.
    
    Args:
        session: The HTTPX session.
        request: A dictionary containing request details from requests.json.
        semaphore: A semaphore for limiting concurrent requests.
    
    Returns:
        List of dictionaries containing results for each tested payload.
    """
    results = []
    url = request["url"]
    method = request.get("method", "GET").upper()
    headers = request.get("headers", {}).copy()
    body = request.get("body")
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # Semaphore to limit concurrency
    async with semaphore:
        # Test GET requests with query parameters
        if method == "GET" and query_params:
            for param, values in query_params.items():
                for payload in SQLI_PAYLOADS:
                    modified_params = query_params.copy()
                    modified_params[param] = [payload for value in values]
                    new_query_string = "&".join(
                        f"{param}={value}" for param, values in modified_params.items() for value in values
                    )
                    new_url = urljoin(url, f"{parsed_url.path}?{new_query_string}")

                    result = await test_SQLI(session, new_url, method, headers=headers)
                    if result and result["SQLI_detected"]:
                        result["query_params"] = query_params  # Original query parameters
                        result["modified_query_params"] = modified_params  # Modified query parameters
                        result["payload"] = payload  # The payload used
                        results.append(result)
                        break  # Break after detecting SQLI and move to the next request

        # Test POST requests with payloads
        elif method == "POST" and body:
            for payload in SQLI_PAYLOADS:
                if isinstance(body, str):
                    modified_body = body + payload
                    logging.debug(f"Modified body size (str): {len(modified_body)}")
                    headers.pop("Content-Length", None)
                    headers["Transfer-Encoding"] = "chunked"  # Add chunked encoding
                elif isinstance(body, dict):
                    modified_body = {key: value + payload for key, value in body.items()}
                    body_str = json.dumps(modified_body)
                    logging.debug(f"Modified body size (dict): {len(body_str)}")
                    headers.pop("Content-Length", None)
                    headers.pop("Transfer-Encoding", None)
                else:
                    modified_body = body

                # Log body size before sending request
                logging.debug(f"Sending request with body size: {len(modified_body)}")

                # Send the request with the modified body
                try:
                    result = await test_SQLI(session, url, method, headers=headers, data=modified_body)
                    if result and result["SQLI_detected"]:
                        result["post_data"] = body  # Original POST data
                        result["modified_post_data"] = modified_body  # Modified POST data with payload
                        result["payload"] = payload  # The payload used
                        results.append(result)
                        break  # Break after detecting SQLI and move to the next request
                except Exception as e:
                    logging.error(f"Error while testing SQLI payload: {e}")
                    continue

        # Path-Based SQLI Detection (only modify path)
        elif method in ("POST", "DELETE", "PATCH", "PUT"):
            path_parts = parsed_url.path.split('/')

            # Look for path segments that could be vulnerable
            for i, part in enumerate(path_parts):
                if part:  # Only modify non-empty path segments
                    for payload in SQLI_PAYLOADS:
                        path_parts[i] = part + payload
                        modified_path = '/'.join(path_parts[:i] + [payload])
                        new_url = urlparse(url)._replace(path=modified_path).geturl()

                        # Send the request with the modified path
                        try:
                            result = await test_SQLI(session, new_url, method, headers=headers)
                            if result and result["SQLI_detected"]:
                                result["path"] = parsed_url.path  # Original path
                                result["modified_path"] = modified_path  # Modified path with payload
                                result["payload"] = payload  # The payload used
                                results.append(result)
                                break  # Break after detecting SQLI and move to the next request
                        except Exception as e:
                            logging.error(f"Error while testing path-based SQLI payload: {e}")
                        path_parts[i] = part  # Reset path segment after testing

    return results

async def test_SQLI(session, url, method, headers=None, data=None):
    """
    Send an HTTP request and test for SQLI vulnerabilities.
    
    Args:
        session: The HTTPX session.
        url: The request URL.
        method: The HTTP method.
        headers: Optional headers for the request.
        data: Optional data for POST requests.
    
    Returns:
        A dictionary with the test results or None if no SQLI is detected.
    """
    try:
        response = await session.request(method, url, headers=headers, data=data, timeout=DEFAULT_TIMEOUT)

        for payload in SQLI_PAYLOADS:
            if pattern.search(response.text): #Detect SQL Errorrs
                return {
                    "url": url,
                    "method": method,
                    "status_code": response.status_code,
                    "SQLI_detected": True,
                    "payload": payload
                }
        return {
            "url": url,
            "method": method,
            "status_code": response.status_code,
            "SQLI_detected": False
        }
    except httpx.RequestError as e:
        logging.error(f"Error testing {url} with payload: {data}. Exception: {e}")
        return {
            "url": url,
            "method": method,
            "status_code": "Error",
            "SQLI_detected": False,
            "error": str(e)
        }
    except Exception as e:
        logging.error(f"Unexpected error testing {url}: {e}")
        return {
            "url": url,
            "method": method,
            "status_code": "Error",
            "SQLI_detected": False,
            "error": str(e)
        }

async def process_requests(requests):
    """
    Process all requests from requests.json and check for SQLI vulnerabilities.
    
    Args:
        requests: A list of request dictionaries.
    
    Returns:
        A list of results from the SQLI tests.
    """
    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)  # Limit concurrent tasks
    async with httpx.AsyncClient() as session:
        tasks = [inject_SQLI_payload(session, request, semaphore) for request in requests]
        results = await asyncio.gather(*tasks)
        return [item for sublist in results for item in sublist]  # Flatten the results

def load_requests(file_path):
    """
    Load requests from requests.json.
    
    Args:
        file_path: Path to the JSON file containing request details.
    
    Returns:
        A list of request dictionaries.
    """
    with open(file_path, 'r') as f:
        return json.load(f)

def save_results(results, output_file):
    """
    Save results to a JSON file.
    
    Args:
        results: List of results from the SQLI tests.
        output_file: Path to the output file.
    """
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)

def save_output_on_exit(sig, frame):
    """Function to save output gracefully when interrupted."""
    logging.info("Saving output before exit...")
    with open("output.json", "w") as f:
        json.dump(requests_data, f, indent=4)
    logging.info("Output saved. Exiting...")
    sys.exit(0)

def print_results(results):
    """
    Print results in a formatted table.
    
    Args:
        results: List of results from the SQLI tests.
    """
    # Filter results to only show detected SQLI vulnerabilities
    SQLI_results = [result for result in results if result["SQLI_detected"]]

    if not SQLI_results:
        print(Fore.YELLOW + "No SQLI vulnerabilities detected.")
        return

    table_data = []
    for result in SQLI_results:
        table_data.append([
            result["url"],
            result["method"],
            result["status_code"],
            Fore.RED + "SQLI Detected"
        ])
    headers = ["URL", "Method", "Status Code", "SQLI Detection"]
    print(tabulate(table_data, headers, tablefmt="grid", stralign="center"))

async def main(input_file, output_file):
    """
    Main function to orchestrate the SQLI detection process.
    
    Args:
        input_file: Path to the input JSON file.
        output_file: Path to the output JSON file.
    """
    requests = load_requests(input_file)
    logging.info(f"Loaded {len(requests)} requests for testing.")

    results = await process_requests(requests)
    # Filter results to only include SQLI detections
    SQLI_results = [result for result in results if result["SQLI_detected"]]

    print_results(SQLI_results)
    save_results(SQLI_results, output_file)
    signal.signal(signal.SIGINT, save_output_on_exit)

if __name__ == "__main__":
    import argparse
    import sys
    import signal

    # Define a signal handler to save results on interrupt
    signal.signal(signal.SIGINT, save_output_on_exit)

    # Command-line argument parsing
    parser = argparse.ArgumentParser(description="SQLI Detection Tool")
    parser.add_argument("--input", default="requests.json", help="Input file with requests (default: requests.json)")
    parser.add_argument("--output", default="SQLI_linux.json", help="Output file for results (default: SQLI_linux.json)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    # Logging configuration
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Run the main function in the asyncio event loop
    try:
        asyncio.run(main(args.input, args.output))
    except KeyboardInterrupt:
        print("\nExecution interrupted by user.")

