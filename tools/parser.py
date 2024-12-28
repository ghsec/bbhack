import os
import json
import argparse
from urllib.parse import urlparse

# Function to save the raw HTTP request to a text file
def save_raw_request_to_file(raw_request, filename):
    if not os.path.exists("reqs"):
        os.makedirs("reqs")  # Ensure the 'reqs' folder exists

    filepath = os.path.join("reqs", filename)
    
    # Open the file and write the raw request to it in plain text
    with open(filepath, "w") as f:
        f.write(raw_request)

# Function to parse the input JSON and create raw HTTP requests
def create_raw_requests(input_file):
    # Open and load the JSON file
    with open(input_file, "r") as f:
        data = json.load(f)
    
    # Iterate through each parsed request data and create the raw HTTP requests
    for idx, item in enumerate(data):
        url = item.get("url", "")
        method = item.get("method", "GET")
        headers = item.get("headers", {})
        query_params = item.get("query_params", "")
        body = item.get("body", None)  # Capture body data if available
        
        # Parse the URL to extract the path (ignore the domain)
        parsed_url = urlparse(url)
        path = parsed_url.path
        if parsed_url.query:
            path += '?' + parsed_url.query  # Add query params if present
        
        # Build the raw request (only path and method, not full URL)
        raw_request = f"{method} {path} HTTP/1.1\n"
        raw_request += f"Host: {parsed_url.netloc}\n"  # Include the host (domain)
        
        # Ensure no duplicate Host header by removing it from the headers
        headers.pop("Host", None)
        
        # Add headers
        for header, value in headers.items():
            raw_request += f"{header}: {value}\n"
        
        # If there is a body (for POST), include it in the body of the request
        if body:
            raw_request += f"\n{body}\n"  # Add the body to the raw request
        
        # If query params exist, add them as a separate line (for info)
        if query_params:
            raw_request += f"Query Parameters: {query_params}\n"
        
        raw_request += "\n"  # Add a newline to separate the request

        # Save the raw request in the 'reqs' folder with a unique filename
        filename = f"request_{idx + 1}.txt"
        save_raw_request_to_file(raw_request, filename)
        print(f"Saved raw request to {filename}")

# Main function to handle argument parsing and invoking the raw request creation
def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Parse JSON file and create raw HTTP requests")
    parser.add_argument("input_file", type=str, help="Path to the input JSON file")
    args = parser.parse_args()

    # Create raw requests from the parsed JSON file
    create_raw_requests(args.input_file)

if __name__ == "__main__":
    main()

