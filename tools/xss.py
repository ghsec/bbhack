import json
import logging
import asyncio
import httpx
from urllib.parse import urlparse, urljoin, urlencode, parse_qs
from tabulate import tabulate
from colorama import init, Fore

# Initialize colorama for colored output
init(autoreset=True)

# Configuration
XSS_PAYLOADS = [
    "injectx<injectx",
    "injectx%3Cinjectx",
    "injectx%u003cinjectx",
    "injectx%26lt;injectx",
    "injectx%26%2360;injectx",
    "injectx%26%23x3c;injectx",
    "aW5qZWN0eDxpbmplY3R4",
    "injectx%253cinjectx"
]
XSS_CONTENT_TYPES = [
    "text/html",
    "application/xhtml+xml",
    "application/xml",
    "text/xml",
    "image/svg+xml",
    "text/xsl",
    "application/vnd.wap.xhtml+xml",
    "text/rdf",
    "application/rdf+xml",
    "application/mathml+xml",
    "text/vtt",
    "text/cache-manifest"
]
DEFAULT_TIMEOUT = 50

# Concurrency limit for async tasks
SEMAPHORE_LIMIT = 5  # You can adjust this value based on your system's capacity

async def inject_xss_payload(session, request, semaphore):
    """
    Inject XSS payloads into the request and test for vulnerabilities, including path-based XSS.
    
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
    headers = request.get("headers", {}).copy()  # Copy headers to modify safely
    body = request.get("body")
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # Semaphore to limit concurrency
    async with semaphore:
        # Test GET requests with query parameters
        if method == "GET" and query_params:
            for param, values in query_params.items():
                for payload in XSS_PAYLOADS:
                    modified_params = query_params.copy()
                    modified_params[param] = [payload for value in values]
                    new_query_string = "&".join(
                        f"{param}={value}" for param, values in modified_params.items() for value in values
                    )
                    new_url = urljoin(url, f"{parsed_url.path}?{new_query_string}")

                    result = await test_xss(session, new_url, method, headers=headers)
                    if result and result["xss_detected"]:
                        # **Capture query parameters in the result**
                        result["query_params"] = query_params  # Original query parameters
                        result["modified_query_params"] = modified_params  # Modified query parameters
                        result["payload"] = payload  # The payload used
                        results.append(result)
                        break  # Stop testing further payloads for this parameter

        # Test POST requests with payloads
        elif method == "POST" and body:
            for payload in XSS_PAYLOADS:
                if isinstance(body, str):
                    # Replace payload in string bodies
                    modified_body = body + payload
                    logging.debug(f"Modified body size (str): {len(modified_body)}")
                    
                    # Check if the body exceeds a reasonable size
                    if len(modified_body) > 2000:  # Adjust the limit as needed
                        logging.debug(f"Skipping payload, body size too large: {len(modified_body)}")
                        continue
                    
                    # Remove Content-Length to let HTTPX calculate it automatically
                    headers.pop("Content-Length", None)
                    headers["Transfer-Encoding"] = "chunked"  # Add chunked encoding
                elif isinstance(body, dict):
                    # Add payload to dictionary bodies
                    modified_body = {key: value + payload for key, value in body.items()}
                    body_str = json.dumps(modified_body)
                    logging.debug(f"Modified body size (dict): {len(body_str)}")
                    
                    # Check if the body exceeds a reasonable size
                    if len(body_str) > 2000:  # Adjust the limit as needed
                        logging.debug(f"Skipping payload, body size too large: {len(body_str)}")
                        continue
                    
                    # Remove Content-Length to let HTTPX calculate it automatically
                    headers.pop("Content-Length", None)
                    headers["Transfer-Encoding"] = "chunked"  # Add chunked encoding
                else:
                    modified_body = body

                # Log body size before sending request
                logging.debug(f"Sending request with body size: {len(modified_body)}")

                # Send the request with the modified body
                try:
                    result = await test_xss(session, url, method, headers=headers, data=modified_body)
                    if result and result["xss_detected"]:
                        # **Capture POST data in the result**
                        result["post_data"] = body  # Original POST data
                        result["modified_post_data"] = modified_body  # Modified POST data with payload
                        result["payload"] = payload  # The payload used
                        results.append(result)
                        break  # Stop testing further payloads
                except Exception as e:
                    logging.error(f"Error while testing XSS payload: {e}")
                    continue

        # Path-Based XSS Detection (only modify path)
        if method == "GET":
            # Modify path parameters with XSS payloads (Do NOT modify query or body here)
            path_parts = parsed_url.path.split('/')

            # Look for path segments that could be vulnerable
            for i, part in enumerate(path_parts):
                if part:  # Only modify non-empty path segments
                    for payload in XSS_PAYLOADS:
                        path_parts[i] = part + payload
                        modified_path = '/'.join(path_parts)
                        new_url = urlparse(url)._replace(path=modified_path).geturl()

                        # Send the request with the modified path
                        try:
                            result = await test_xss(session, new_url, method, headers=headers)
                            if result and result["xss_detected"]:
                                # **Capture path-based XSS in the result**
                                result["path"] = parsed_url.path  # Original path
                                result["modified_path"] = modified_path  # Modified path with payload
                                result["payload"] = payload  # The payload used
                                results.append(result)
                                break  # Stop testing further payloads for this path segment
                        except Exception as e:
                            logging.error(f"Error while testing path-based XSS payload: {e}")
                        path_parts[i] = part  # Reset path segment after testing

    return results


async def test_xss(session, url, method, headers=None, data=None):
    """
    Send an HTTP request and test for XSS vulnerabilities.
    
    Args:
        session: The HTTPX session.
        url: The request URL.
        method: The HTTP method.
        headers: Optional headers for the request.
        data: Optional data for POST requests.
    
    Returns:
        A dictionary with the test results or None if no reflection is detected.
    """
    try:
        response = await session.request(method, url, headers=headers, data=data, timeout=DEFAULT_TIMEOUT)
        content_type = response.headers.get("Content-Type", "")

        if any(ct in content_type for ct in XSS_CONTENT_TYPES):
            for payload in XSS_PAYLOADS:
                if "injectx<injectx" in response.text:
                    return {
                        "url": url,
                        "method": method,
                        "status_code": response.status_code,
                        "content_type": content_type,
                        "xss_detected": True,
                        "payload": payload
                    }
        return {
            "url": url,
            "method": method,
            "status_code": response.status_code,
            "content_type": content_type,
            "xss_detected": False
        }
    except httpx.RequestError as e:
        logging.error(f"Error testing {url} with payload: {data}. Exception: {e}")
        return {
            "url": url,
            "method": method,
            "status_code": "Error",
            "content_type": "N/A",
            "xss_detected": False,
            "error": str(e)
        }
    except Exception as e:
        logging.error(f"Unexpected error testing {url}: {e}")
        return {
            "url": url,
            "method": method,
            "status_code": "Error",
            "content_type": "N/A",
            "xss_detected": False,
            "error": str(e)
        }

async def process_requests(requests):
    """
    Process all requests from requests.json and check for XSS vulnerabilities.
    
    Args:
        requests: A list of request dictionaries.
    
    Returns:
        A list of results from the XSS tests.
    """
    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)  # Limit concurrent tasks
    async with httpx.AsyncClient() as session:
        tasks = [inject_xss_payload(session, request, semaphore) for request in requests]
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
        results: List of results from the XSS tests.
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
        results: List of results from the XSS tests.
    """
    # Filter results to only show detected XSS vulnerabilities
    xss_results = [result for result in results if result["xss_detected"]]

    if not xss_results:
        print(Fore.YELLOW + "No XSS vulnerabilities detected.")
        return

    table_data = []
    for result in xss_results:
        table_data.append([
            result["url"],
            result["method"],
            result["status_code"],
            result["content_type"],
            Fore.RED + "XSS Detected"
        ])
    headers = ["URL", "Method", "Status Code", "Content Type", "XSS Detection"]
    print(tabulate(table_data, headers, tablefmt="grid", stralign="center"))

async def main(input_file, output_file):
    """
    Main function to orchestrate the XSS detection process.
    
    Args:
        input_file: Path to the input JSON file.
        output_file: Path to the output JSON file.
    """
    requests = load_requests(input_file)
    logging.info(f"Loaded {len(requests)} requests for testing.")

    results = await process_requests(requests)
    # Filter results to only include XSS detections
    xss_results = [result for result in results if result["xss_detected"]]

    print_results(xss_results)
    save_results(xss_results, output_file)
    signal.signal(signal.SIGINT, save_output_on_exit)

if __name__ == "__main__":
    import argparse
    import sys
    import signal

    # Define a signal handler to save results on interrupt
    def save_output_on_exit(signal_num, frame):
        print("\nGracefully exiting and saving results...")
        with open("output.json", "w") as f:
            json.dump(requests_data, f, indent=4)
        sys.exit(0)

    # Add the signal handler for `Ctrl+C`
    signal.signal(signal.SIGINT, save_output_on_exit)

    # Command-line argument parsing
    parser = argparse.ArgumentParser(description="XSS Detection Tool")
    parser.add_argument("--input", default="requests.json", help="Input file with requests (default: requests.json)")
    parser.add_argument("--output", default="results-xss.json", help="Output file for results (default: results-xss.json)")
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
