import json
import argparse
import os
from urllib.parse import urlparse, unquote

# Argument parser setup
parser = argparse.ArgumentParser(description="Extract raw requests from a HAR file")
parser.add_argument('-f', '--file', type=str, required=True, help="Path to the HAR file")
parser.add_argument('-o', '--output', type=str, required=False, default="har_requests", help="Directory to save raw requests")
parser.add_argument('-s', '--scope', type=str, required=False, help="Extract only requests matching this host")

# Parse the input arguments
args = parser.parse_args()

# Ensure the HAR file exists
har_file_path = args.file
output_dir = args.output
scope = args.scope

# List of file extensions to ignore
excluded_extensions = (
    ".png", ".apng", ".bmp", ".gif", ".ico", ".cur", ".jpg", ".jpeg", ".jfif", ".pjp", ".pjpeg", ".svg",
    ".tif", ".tiff", ".webp", ".xbm", ".3gp", ".aac", ".flac", ".mpg", ".mpeg", ".mp3", ".mp4", ".m4a",
    ".m4v", ".m4p", ".oga", ".ogg", ".ogv", ".mov", ".wav", ".webm", ".eot", ".woff", ".woff2", ".ttf", 
    ".otf", ".css", ".js", ".json"
)

if not os.path.exists(har_file_path):
    print(f"Error: The file {har_file_path} does not exist.")
    exit(1)

# Create the output directory for saving the raw requests
os.makedirs(output_dir, exist_ok=True)

# Load and process the HAR file
with open(har_file_path, 'r', encoding='utf-8') as file:
    har_data = json.load(file)

# Track unique requests (deduplication)
unique_requests = set()

# Loop through the entries and extract raw HTTP requests
entries = har_data.get('log', {}).get('entries', [])
if not entries:
    print("No entries found in the HAR file.")
    exit(1)

# Counter for scoped requests
saved_count = 0

for index, entry in enumerate(entries):
    request = entry.get('request', {})
    method = request.get('method', 'UNKNOWN')
    url = request.get('url', 'UNKNOWN')
    
    # Parse the URL and extract components
    parsed_url = urlparse(url)
    host = parsed_url.hostname
    path = parsed_url.path or '/'
    
    # If the URL has a query, add it to the path
    if parsed_url.query:
        path += '?' + parsed_url.query
    
    # Check if the URL path ends with an excluded extension
    file_extension = os.path.splitext(unquote(path))[1].lower()
    if file_extension in excluded_extensions:
        continue  # Skip this request if it has an excluded extension
    
    # If scope is set, filter requests by host
    if scope and host != scope:
        continue
    
    # Extract headers and raw request details
    headers = request.get('headers', [])
    post_data = request.get('postData', {}).get('text', '')

    # Create a unique key for deduplication (based on method, path, and headers)
    headers_str = ''.join([f"{header['name'].lower()}: {header['value']}" for header in headers if not header['name'].startswith(":") and header['name'].lower() != 'host'])
    unique_key = f"{method} {path} {headers_str}"

    if unique_key in unique_requests:
        continue  # Skip if the request has already been processed
    
    unique_requests.add(unique_key)  # Mark the request as processed

    # Build the raw request text with the relative path and Host header
    raw_request = f"{method} {path} HTTP/1.1\n"
    raw_request += f"Host: {host}\n"  # Explicit Host header
    
    for header in headers:
        header_name = header.get('name')
        if not header_name.startswith(":") and header_name.lower() != 'host':  # Ignore pseudo-headers and duplicate Host
            raw_request += f"{header_name}: {header.get('value')}\n"
    
    raw_request += "\n"  # Blank line between headers and body (if any)
    raw_request += post_data if post_data else ""
    
    # Save each request into a separate .txt file
    request_filename = os.path.join(output_dir, f"request_{saved_count + 1}.txt")
    with open(request_filename, 'w', encoding='utf-8') as request_file:
        request_file.write(raw_request)
    
    saved_count += 1
    print(f"Saved request {saved_count} to {request_filename}")

if saved_count == 0:
    print(f"No requests matched the scope '{scope}'.")
else:
    print(f"All requests saved to {output_dir}/")

