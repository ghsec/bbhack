import os
import base64
import argparse
import xml.etree.ElementTree as ET

# Function to extract, decode, and deduplicate requests
def extract_requests_from_xml(file_path, output_dir):
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Read the XML content
    with open(file_path, 'r', encoding='utf-8') as file:
        xml_content = file.read()

    # Parse the XML content
    root = ET.fromstring(xml_content)

    # Counter to name the request files
    file_counter = 1
    seen_requests = set()  # Set to track unique requests

    # Iterate through each <item> in the XML
    for item in root.findall('item'):
        # Extract and decode the base64 encoded request
        request_element = item.find('request')
        if request_element is not None and 'base64' in request_element.attrib and request_element.attrib['base64'] == 'true':
            encoded_request = request_element.text.strip()
            decoded_request = base64.b64decode(encoded_request).decode('utf-8')

            # Check if the request is unique
            if decoded_request not in seen_requests:
                # Add the request to the set of seen requests
                seen_requests.add(decoded_request)

                # Save the request into a separate file
                file_name = f'request_{file_counter}.txt'
                file_path = os.path.join(output_dir, file_name)
                with open(file_path, 'w', encoding='utf-8') as req_file:
                    req_file.write(decoded_request)

                print(f"Saved: {file_name}")
                file_counter += 1
            else:
                print("Duplicate request found, skipping...")

# Function to handle command-line arguments
def main():
    parser = argparse.ArgumentParser(description="Extract, decode, and deduplicate base64 requests from an XML file.")
    
    # Add -f for input file and -o for output directory
    parser.add_argument('-f', '--file', required=True, help='Path to the input XML file')
    parser.add_argument('-o', '--output', required=True, help='Directory to save the extracted requests')

    # Parse the arguments
    args = parser.parse_args()

    # Extract, deduplicate, and save the requests
    extract_requests_from_xml(args.file, args.output)

if __name__ == '__main__':
    main()

