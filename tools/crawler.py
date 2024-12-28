import time
import json
import logging
import re
import random
import string
import secrets
from urllib.parse import urljoin, urlparse
from seleniumwire import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import (
    WebDriverException,
    TimeoutException,
    ElementClickInterceptedException,
    StaleElementReferenceException,
    NoSuchElementException,
    ElementNotInteractableException,
)
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys  # Added import for Keys
import argparse
import signal
import sys


# Initialize logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# Global variable to store requests data
requests_data = []


def initialize_driver():
    chrome_options = Options()
    # Comment out the headless mode for debugging
    # chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--window-size=1920x1080")
    return webdriver.Chrome(options=chrome_options)


def is_in_scope(base_url, url):
    """Check if a URL is within the same domain as the base URL."""
    base_netloc = urlparse(base_url).netloc
    target_netloc = urlparse(url).netloc
    return base_netloc == target_netloc


def safe_get(driver, url, retries=3, delay=2):
    """Navigate to a URL with retries and error handling."""
    for attempt in range(retries):
        try:
            driver.get(url)
            WebDriverWait(driver, 120).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            logging.info(f"Successfully loaded {url}")
            return True
        except (WebDriverException, TimeoutException, NoSuchElementException, ElementNotInteractableException) as e:
            logging.warning(f"Failed to load {url}, retrying... ({attempt + 1}/{retries}) - Error: {e}")
            time.sleep(random.uniform(delay, delay + 2))  # Random delay between retries
    logging.error(f"Failed to load {url} after {retries} attempts.")
    return False


def login(driver, login_url, username, password):
    """Log in to a website using provided credentials."""
    safe_get(driver, login_url)
    try:
        logging.info("Attempting to find the username field.")
        username_field = WebDriverWait(driver, 30).until(
            EC.visibility_of_element_located((By.CSS_SELECTOR, "#user_email"))
        )
        username_field.clear()
        username_field.send_keys(username)
        logging.info("Username entered successfully.")

        logging.info("Attempting to find the password field.")
        password_field = driver.find_element(By.CSS_SELECTOR, "#user_password")
        password_field.clear()
        password_field.send_keys(password)
        logging.info("Password entered successfully.")

        logging.info("Attempting to press Enter instead of clicking the login button.")
        password_field.send_keys(Keys.RETURN)

        logging.info("Waiting for the page to redirect after login.")
        WebDriverWait(driver, 30).until(
            EC.url_changes(login_url)
        )
        logging.info("Login successful, redirected to a new page.")
    except Exception as e:
        logging.error(f"Login failed: {e}")
        raise


def fill_random_inputs_and_submit(driver):
    """
    Detect input and textarea fields on the current page, fill them with random strings,
    and click the first submit or button element.
    """
    try:
        # Find all input elements and textarea elements
        input_elements = driver.find_elements(By.TAG_NAME, "input")
        textarea_elements = driver.find_elements(By.TAG_NAME, "textarea")
        
        # Fill input fields with random data
        for input_element in input_elements:
            try:
                input_type = input_element.get_attribute("type") or input_element.get_attribute("class")
                
                # Exclude non-fillable input types
                if input_type in ["submit", "reset", "button", "hidden", None]:
                    continue
                
                # Generate a random string
                random_string = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
                
                # Fill the input field
                input_element.clear()
                input_element.send_keys(random_string)
                
                # Log the action
                logging.info(f"Filled input field with random string: {random_string}")
            except Exception as e:
                logging.warning(f"Failed to fill input field: {e}")

        # Fill textarea elements with random data
        for textarea_element in textarea_elements:
            try:
                # Generate a random string
                random_string = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
                
                # Fill the textarea field
                textarea_element.clear()
                textarea_element.send_keys(random_string)
                
                # Log the action
                logging.info(f"Filled textarea field with random string: {random_string}")
            except Exception as e:
                logging.warning(f"Failed to fill textarea field: {e}")
        
        # Find and click the first submit or button element after filling the form
        button_elements = driver.find_elements(By.XPATH,
            "//input[@type='submit'] | //button | //input[@type='button'] | //input[@type='reset'] | //input[@type='image'] | //button[contains(@class, 'your-button-class')] | //button[@id='your-button-id'] | //button[text()='Submit'] | //button[contains(text(), 'Submit')] | //form//button | //div[@class='button-container']//button | //a[@role='button'] | //a[text()='Click here'] | //*[@id='loginButton']"
        )

        for button in button_elements:
            try:
                if button.is_displayed() and button.is_enabled():  # Ensure the button is visible and clickable 
#                    button.click()
                    logging.info("Clicked the button successfully.")
                    break  # Stop once we click the first available button
                    
                    
            except Exception as e:
                logging.warning(f"Failed to click button: {e}")
                
    except Exception as e:
        logging.error(f"Error while detecting or filling input fields: {e}")



def capture_requests_for_page(driver, base_url, current_url, requests_data, visited_links, exclude_pattern):
    """Capture requests for a single page, ensuring all requests in scope are captured."""
    for request in driver.requests:
        if request.response:
            # Exclude requests with unwanted file extensions or out-of-scope URLs
            if exclude_pattern.search(request.url) or not is_in_scope(base_url, request.url):
                logging.info(f"Excluded request: {request.url}")
                continue

            # Create a unique key for the request (e.g., using URL and HTTP method)
            request_key = (request.url, request.method)

            # If the request hasn't been captured yet, add it to the list
            if request_key not in visited_links:
                visited_links.add(request_key)
                requests_data.append({
                    "url": request.url,
                    "method": request.method,
                    "status_code": request.response.status_code,
                    "headers": dict(request.headers),
                    "response_headers": dict(request.response.headers),
                    "body": request.body.decode('utf-8', errors='replace') if request.body else None,
                    "parent_url": current_url,
                    "timestamp": time.time(),
                })


def crawl_and_capture_requests(base_url, output_file, max_depth, exclude_extensions, auth_required=False, login_url=None, username=None, password=None):
    """Crawl the website and capture HTTP requests."""
    driver = initialize_driver()
    visited_links = set()
    links_to_visit = [(base_url, 0)]

    # Regex to exclude extensions
    exclude_pattern = re.compile(rf"(?i)\.({'|'.join(map(re.escape, exclude_extensions))})(?:\?|#|$)")

    if auth_required:
        login(driver, login_url, username, password)

    try:
        while links_to_visit:
            current_url, current_depth = links_to_visit.pop(0)
            if current_url in visited_links or current_depth > max_depth:
                continue

            if not safe_get(driver, current_url):
                continue

            visited_links.add(current_url)
            logging.info(f"Visited: {current_url} (Depth: {current_depth})")

            # Fill input fields with random strings
            fill_random_inputs_and_submit(driver)

            # Capture requests for the current page
            capture_requests_for_page(driver, base_url, current_url, requests_data, visited_links, exclude_pattern)

            # Extract new links
            new_links = driver.find_elements(By.TAG_NAME, "a")
            for new_element in new_links:
                try:
                    href = new_element.get_attribute("href")
                    if href and is_in_scope(base_url, href):  # Only follow links in scope
                        absolute_url = urljoin(current_url, href)
                        if absolute_url not in visited_links:
                            links_to_visit.append((absolute_url, current_depth + 1))
                except StaleElementReferenceException:
                    logging.warning(f"StaleElementReferenceException encountered, retrying link extraction.")

        # Save captured requests to file
        with open(output_file, "w") as f:
            json.dump(requests_data, f, indent=4)

    finally:
        driver.quit()


def save_output_on_exit(sig, frame):
    """Function to save output gracefully when interrupted."""
    logging.info("Saving output before exit...")
    with open("requests.json", "w") as f:
        json.dump(requests_data, f, indent=4)
    logging.info("Output saved. Exiting...")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Website crawler to capture HTTP requests.")
    parser.add_argument("-t", "--target", required=True, help="Target URL to start crawling.")
    parser.add_argument("-o", "--output", required=True, help="Output file to save captured requests.")
    parser.add_argument("-d", "--depth", type=int, default=4, help="Maximum crawl depth (default: 4).")
    parser.add_argument("-a", "--auth", action="store_true", help="Enable authentication.")
    parser.add_argument("-l", "--login-url", help="Login page URL.")
    parser.add_argument("-u", "--username", help="Username for login.")
    parser.add_argument("-p", "--password", help="Password for login.")
    parser.add_argument("--exclude", nargs="*", default=["png", "apng", "bmp", "gif", "ico", "cur", "jpg", "jpeg", "jfif", "pjp", "pjpeg", "svg", "tif", "tiff", "webp", "xbm", "3gp", "aac", "flac", "mpg", "mpeg", "mp3", "mp4", "m4a", "m4v", "m4p", "oga", "ogg", "ogv", "mov", "wav", "webm", "eot", "woff", "woff2", "ttf", "otf", "css", "js", "pdf"], help="File extensions to exclude (default: png, jpg, css, etc...).")
    args = parser.parse_args()

    # Register the signal handler for graceful exit
    signal.signal(signal.SIGINT, save_output_on_exit)

    # Start crawling and capturing
    crawl_and_capture_requests(args.target, args.output, args.depth, args.exclude, args.auth, args.login_url, args.username, args.password)


if __name__ == "__main__":
    main()
