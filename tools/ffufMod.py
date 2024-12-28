import os
import json
import urllib.parse
import argparse
import re

def mark_parameters_in_headers(headers):
    marked_headers = []
    for header in headers:
        if ':' in header:
            key, value = header.split(':', 1)
            key = key.strip()
            value = value.strip()
            # Preserve the Host header exactly as it is, without marking
            if key.lower() == "host":
                marked_headers.append(f"{key}: {value}")
            elif key.lower() == "cookie":
                # Special handling for cookies
                cookies = [cookie.strip() for cookie in value.split(';')]
                marked_cookies = []
                for cookie in cookies:
                    if '=' in cookie:
                        name, val = cookie.split('=', 1)
                        marked_cookies.append(f"{name.strip()}=§{val.strip()}§")
                    else:
                        marked_cookies.append(cookie.strip())
                marked_headers.append(f"{key}: {'; '.join(marked_cookies)}")
            else:
                marked_headers.append(f"{key}: §{value}§")
        else:
            marked_headers.append(header)
    return marked_headers

def mark_parameters_in_url(url):
    if '?' in url:
        # URL includes query parameters, so process normally
        path, query_string = url.split('?', 1)
        parsed_params = urllib.parse.parse_qs(query_string)
        # Manually mark values without URL-encoding
        marked_params = []
        for key, values in parsed_params.items():
            for value in values:
                marked_params.append(f"{key}=§{value}§")
        marked_query_string = "&".join(marked_params)
        return f"{path}?{marked_query_string}"
    else:
        # No query parameters, so mark the last path segment
        path_segments = url.rstrip('/').split('/')
        # Mark only the last segment
        path_segments[-1] = f"{path_segments[-1]}/§§"
        marked_path = "/".join(path_segments)
        return marked_path

def mark_value(value):
    """Helper function to mark a single value."""
    return f"§{value}§"

def mark_json_value(value):
    """Helper function to mark JSON values correctly."""
    if isinstance(value, str):
        # Check if the string is wrapped in single quotes
        if value.startswith("'") and value.endswith("'"):
            return f"§{value[1:-1]}§"  # Remove quotes and mark
        return mark_value(value)
    elif isinstance(value, list):
        return [mark_json_value(item) for item in value]
    elif isinstance(value, dict):
        return {key: mark_json_value(val) for key, val in value.items()}
    else:
        return mark_value(value)

def mark_parameters_in_body(body):
    try:
        # Try parsing the body as JSON
        data = json.loads(body)
        marked_data = mark_json_value(data)  # Use the new marking function
        return json.dumps(marked_data, ensure_ascii=False, indent=2)  # Maintain unicode and pretty print

    except json.JSONDecodeError:
        # If it's not JSON, assume it's URL-encoded form data
        parsed_params = urllib.parse.parse_qs(body)
        marked_params = []
        for key, values in parsed_params.items():
            for value in values:
                marked_params.append(f"{key}=§{value}§")
        return "&".join(marked_params)

def process_request(raw_request):
    lines = raw_request.splitlines()
    request_line = lines[0]
    headers = []
    body = None
    empty_line_index = None

    # Split headers and body
    for i, line in enumerate(lines):
        if line.strip() == "":
            empty_line_index = i
            break
        headers.append(line)

    if empty_line_index is not None and empty_line_index < len(lines) - 1:
        body = lines[empty_line_index + 1]

    # Process request line (handling GET parameters)
    method, url, http_version = request_line.split(" ", 2)
    marked_url = mark_parameters_in_url(url)
    marked_request_line = f"{method} {marked_url} {http_version}"

    # Process headers
    marked_headers = mark_parameters_in_headers(headers[1:])

    # Process body
    marked_body = mark_parameters_in_body(body) if body else None

    # Reconstruct the modified request
    modified_request = [marked_request_line] + marked_headers
    if marked_body:
        modified_request.append("")  # Blank line between headers and body
        modified_request.append(marked_body)

    return "\n".join(modified_request)

def process_files(input_dir, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for filename in os.listdir(input_dir):
        input_file_path = os.path.join(input_dir, filename)
        if os.path.isfile(input_file_path):
            with open(input_file_path, 'r') as file:
                raw_request = file.read()
                modified_request = process_request(raw_request)

            output_file_path = os.path.join(output_dir, filename)
            with open(output_file_path, 'w') as output_file:
                output_file.write(modified_request)

def main():
    parser = argparse.ArgumentParser(description="Mark raw request parameters with §")
    parser.add_argument("-p", "--path", required=True, help="Input directory containing raw request files")
    parser.add_argument("-o", "--output", required=True, help="Output directory to save modified request files")
    args = parser.parse_args()

    process_files(args.path, args.output)

if __name__ == "__main__":
    main()
