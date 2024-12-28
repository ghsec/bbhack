import os
import json
import urllib.parse
import argparse
import re

def mark_parameters_in_headers(headers, wrap_headers, wrap_cookies):
    marked_headers = []
    for header in headers:
        if ':' in header:
            key, value = header.split(':', 1)
            key = key.strip()
            value = value.strip()
            if key.lower() == "host":
                marked_headers.append(f"{key}: {value}")
            elif key.lower() == "cookie" and wrap_cookies:
                cookies = [cookie.strip() for cookie in value.split(';')]
                marked_cookies = []
                for cookie in cookies:
                    if '=' in cookie:
                        name, val = cookie.split('=', 1)
                        marked_cookies.append(f"{name.strip()}=§{val.strip()}§")
                    else:
                        marked_cookies.append(cookie.strip())
                marked_headers.append(f"{key}: {'; '.join(marked_cookies)}")
            elif wrap_headers:
                marked_headers.append(f"{key}: §{value}§")
            else:
                marked_headers.append(f"{key}: {value}")
        else:
            marked_headers.append(header)
    return marked_headers

def mark_parameters_in_url(url, wrap_path, wrap_query):
    if '?' in url and wrap_query:
        path, query_string = url.split('?', 1)
        parsed_params = urllib.parse.parse_qs(query_string)
        marked_params = []
        for key, values in parsed_params.items():
            for value in values:
                marked_params.append(f"{key}=§{value}§")
        marked_query_string = "&".join(marked_params)
        return f"{path}?{marked_query_string}"
    elif not '?' in url and wrap_path:
        path_segments = url.rstrip('/').split('/')
        path_segments[-1] = f"{path_segments[-1]}§§"
        return "/".join(path_segments)
    return url

def mark_json_value(value):
    if isinstance(value, str):
        if value.startswith("'") and value.endswith("'"):
            return f"§{value[1:-1]}§"
        return f"§{value}§"
    elif isinstance(value, list):
        return [mark_json_value(item) for item in value]
    elif isinstance(value, dict):
        return {key: mark_json_value(val) for key, val in value.items()}
    else:
        return f"§{value}§"

def mark_parameters_in_body(body, wrap_body):
    if not wrap_body:
        return body
    try:
        data = json.loads(body)
        marked_data = mark_json_value(data)
        return json.dumps(marked_data, ensure_ascii=False, indent=2)
    except json.JSONDecodeError:
        parsed_params = urllib.parse.parse_qs(body)
        marked_params = []
        for key, values in parsed_params.items():
            for value in values:
                marked_params.append(f"{key}=§{value}§")
        return "&".join(marked_params)

def process_request(raw_request, wrap_path, wrap_query, wrap_headers, wrap_cookies, wrap_body):
    lines = raw_request.splitlines()
    request_line = lines[0]
    headers = []
    body = None
    empty_line_index = None

    for i, line in enumerate(lines):
        if line.strip() == "":
            empty_line_index = i
            break
        headers.append(line)

    if empty_line_index is not None and empty_line_index < len(lines) - 1:
        body = lines[empty_line_index + 1]

    method, url, http_version = request_line.split(" ", 2)
    marked_url = mark_parameters_in_url(url, wrap_path, wrap_query)
    marked_request_line = f"{method} {marked_url} {http_version}"

    marked_headers = mark_parameters_in_headers(headers[1:], wrap_headers, wrap_cookies)

    marked_body = mark_parameters_in_body(body, wrap_body) if body else None

    modified_request = [marked_request_line] + marked_headers
    if marked_body:
        modified_request.append("")
        modified_request.append(marked_body)

    return "\n".join(modified_request)

def process_files(input_dir, output_dir, wrap_path, wrap_query, wrap_headers, wrap_cookies, wrap_body):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for filename in os.listdir(input_dir):
        input_file_path = os.path.join(input_dir, filename)
        if os.path.isfile(input_file_path):
            with open(input_file_path, 'r') as file:
                raw_request = file.read()
                modified_request = process_request(
                    raw_request, wrap_path, wrap_query, wrap_headers, wrap_cookies, wrap_body
                )

            output_file_path = os.path.join(output_dir, filename)
            with open(output_file_path, 'w') as output_file:
                output_file.write(modified_request)

def main():
    parser = argparse.ArgumentParser(description="Mark raw request parameters with §")
    parser.add_argument("-p", "--path", required=True, help="Input directory containing raw request files")
    parser.add_argument("-o", "--output", required=True, help="Output directory to save modified request files")
    parser.add_argument("-wp", "--wrap-path", action="store_false", help="Wrap only paths")
    parser.add_argument("-wc", "--wrap-cookie", action="store_true", help="Wrap only cookies")
    parser.add_argument("-wh", "--wrap-header", action="store_true", help="Wrap only headers")
    parser.add_argument("-wq", "--wrap-query", action="store_false", help="Wrap only query parameters")
    parser.add_argument("-wb", "--wrap-body", action="store_false", help="Wrap only body parameters")

    args = parser.parse_args()

    process_files(
        args.path,
        args.output,
        args.wrap_path,
        args.wrap_query,
        args.wrap_header,
        args.wrap_cookie,
        args.wrap_body
    )

if __name__ == "__main__":
    main()

