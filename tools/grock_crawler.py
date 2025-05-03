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
from selenium.webdriver.common.keys import Keys
import argparse
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed  # Added for parallel crawling

# Initialize logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Global variable to store requests data
requests_data = []

# Improvement: Add mutex for thread-safe access to requests_data and visited_links
import threading
data_lock = threading.Lock()

def initialize_driver():
    chrome_options = Options()
    # chrome_options.add_argument("--headless")  # Uncomment for headless mode
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
            time.sleep(random.uniform(delay, delay + 2))
    logging.error(f"Failed to load {url} after {retries} attempts.")
    return False

def detect_login_fields(driver):
    """Dynamically detect username/email and password fields."""
    try:
        # Common attributes for username/email fields
        username_patterns = re.compile(r"(user|email|login|account)", re.IGNORECASE)
        password_patterns = re.compile(r"pass(word)?|pwd", re.IGNORECASE)

        # Find all input fields
        inputs = driver.find_elements(By.TAG_NAME, "input")
        username_field = None
        password_field = None

        for input_elem in inputs:
            input_id = input_elem.get_attribute("id") or ""
            input_name = input_elem.get_attribute("name") or ""
            input_type = input_elem.get_attribute("type") or ""
            placeholder = input_elem.get_attribute("placeholder") or ""

            # Check for username/email field
            if (username_patterns.search(input_id) or
                username_patterns.search(input_name) or
                username_patterns.search(placeholder) or
                input_type == "email"):
                username_field = input_elem
            # Check for password field
            if (password_patterns.search(input_id) or
                password_patterns.search(input_name) or
                password_patterns.search(placeholder) or
                input_type == "password"):
                password_field = input_elem

        return username_field, password_field
    except Exception as e:
        logging.error(f"Failed to detect login fields: {e}")
        return None, None

def login(driver, login_url, username, password, max_attempts=2):
    """Log in to a website with dynamic field detection and session expiration handling."""
    for attempt in range(max_attempts):
        safe_get(driver, login_url)
        try:
            username_field, password_field = detect_login_fields(driver)
            if not username_field or not password_field:
                logging.error("Could not find username or password fields.")
                raise Exception("Login field detection failed")

            username_field.clear()
            username_field.send_keys(username)
            logging.info("Username entered successfully.")

            password_field.clear()
            password_field.send_keys(password)
            logging.info("Password entered successfully.")

            password_field.send_keys(Keys.RETURN)
            logging.info("Submitted login form.")

            WebDriverWait(driver, 30).until(EC.url_changes(login_url))
            logging.info("Login successful, redirected to a new page.")
            return True
        except Exception as e:
            logging.error(f"Login attempt {attempt + 1} failed: {e}")
            time.sleep(random.uniform(1, 3))
    logging.error("Login failed after maximum attempts.")
    return False

def generate_input_data(input_type, maxlength=None):
    """Generate type-specific random data for input fields."""
    length = min(maxlength, 10) if maxlength else 10
    if input_type == "email":
        return f"{''.join(secrets.choice(string.ascii_lowercase) for _ in range(5))}@example.com"
    elif input_type == "number":
        return ''.join(secrets.choice(string.digits) for _ in range(length))
    elif input_type == "tel":
        return ''.join(secrets.choice(string.digits) for _ in range(10))
    else:
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

def fill_random_inputs_and_submit(driver):
    """Fill input/textarea fields with type-specific data and submit the form."""
    try:
        input_elements = driver.find_elements(By.TAG_NAME, "input")
        textarea_elements = driver.find_elements(By.TAG_NAME, "textarea")

        for input_element in input_elements:
            try:
                input_type = input_element.get_attribute("type") or "text"
                if input_type in ["submit", "reset", "button", "hidden"]:
                    continue
                maxlength = int(input_element.get_attribute("maxlength")) if input_element.get_attribute("maxlength") else None
                random_data = generate_input_data(input_type, maxlength)
                input_element.clear()
                input_element.send_keys(random_data)
                logging.info(f"Filled input (type={input_type}) with: {random_data}")
            except Exception as e:
                logging.warning(f"Failed to fill input field: {e}")

        for textarea_element in textarea_elements:
            try:
                random_data = generate_input_data("text")
                textarea_element.clear()
                textarea_element.send_keys(random_data)
                logging.info(f"Filled textarea with: {random_data}")
            except Exception as e:
                logging.warning(f"Failed to fill textarea field: {e}")

        # Improvement: Narrowed button selection to form-related buttons
        button_elements = driver.find_elements(By.XPATH,
            "//form//input[@type='submit'] | //form//button | "
            "//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'submit')] | "
            "//button[@type='submit'] | //input[@type='button' and contains(@value, 'Submit')]"
        )
        for button in button_elements:
            try:
                if button.is_displayed() and button.is_enabled():
                    button.click()
                    logging.info("Clicked submit button successfully.")
                    break
            except Exception as e:
                logging.warning(f"Failed to click button: {e}")
    except Exception as e:
        logging.error(f"Error while detecting or filling input fields: {e}")

def capture_requests_for_page(driver, base_url, current_url, visited_links, exclude_pattern):
    """Capture requests for a single page, ensuring thread-safe data collection."""
    for request in driver.requests:
        if request.response and not exclude_pattern.search(request.url) and is_in_scope(base_url, request.url):
            request_key = (request.url, request.method)
            with data_lock:  # Thread-safe access
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

def process_page(driver, base_url, current_url, current_depth, max_depth, visited_links, exclude_pattern, auth_required, login_url, username, password, delay):
    """Process a single page, handling session expiration and capturing data."""
    if current_url in visited_links or current_depth > max_depth:
        return []

    # Improvement: Check for session expiration
    if auth_required and login_url in driver.current_url:
        logging.info("Session expired, attempting to re-authenticate.")
        if not login(driver, login_url, username, password):
            logging.error("Re-authentication failed, skipping page.")
            return []

    if not safe_get(driver, current_url):
        return []

    with data_lock:  # Thread-safe access
        visited_links.add(current_url)
    logging.info(f"Visited: {current_url} (Depth: {current_depth})")

    fill_random_inputs_and_submit(driver)
    capture_requests_for_page(driver, base_url, current_url, visited_links, exclude_pattern)

    new_links = []
    try:
        link_elements = driver.find_elements(By.TAG_NAME, "a")
        for elem in link_elements:
            href = elem.get_attribute("href")
            if href and is_in_scope(base_url, href):
                absolute_url = urljoin(current_url, href)
                if absolute_url not in visited_links:
                    new_links.append((absolute_url, current_depth + 1))
    except StaleElementReferenceException:
        logging.warning("StaleElementReferenceException encountered, skipping link extraction.")

    # Improvement: Add delay to respect rate limiting
    time.sleep(random.uniform(delay, delay + 0.5))
    return new_links

def crawl_and_capture_requests(base_url, output_file, max_depth, exclude_extensions, auth_required=False, login_url=None, username=None, password=None, max_workers=2, delay=1.0):
    """Crawl the website and capture HTTP requests with parallel processing."""
    visited_links = set()
    links_to_visit = [(base_url, 0)]
    exclude_pattern = re.compile(rf"(?i)\.({'|'.join(map(re.escape, exclude_extensions))})(?:\?|#|$)")
    
    # Main driver for initial login
    main_driver = initialize_driver()
    try:
        if auth_required and not login(main_driver, login_url, username, password):
            logging.error("Initial login failed, aborting crawl.")
            return

        # Improvement: Parallel crawling with ThreadPoolExecutor
        while links_to_visit:
            # Create a batch of links to process in parallel
            batch = links_to_visit[:max_workers]
            links_to_visit = links_to_visit[max_workers:]

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Create a driver for each worker
                drivers = [initialize_driver() for _ in range(len(batch))]
                try:
                    future_to_url = {
                        executor.submit(
                            process_page,
                            driver,
                            base_url,
                            url,
                            depth,
                            max_depth,
                            visited_links,
                            exclude_pattern,
                            auth_required,
                            login_url,
                            username,
                            password,
                            delay
                        ): url for driver, (url, depth) in zip(drivers, batch)
                    }
                    for future in as_completed(future_to_url):
                        new_links = future.result()
                        with data_lock:  # Thread-safe access
                            links_to_visit.extend(new_links)
                finally:
                    for driver in drivers:
                        driver.quit()

        # Save captured requests
        with open(output_file, "w") as f:
            json.dump(requests_data, f, indent=4)
    finally:
        main_driver.quit()

def save_output_on_exit(sig, frame):
    """Save output gracefully when interrupted."""
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
    parser.add_argument("--exclude", nargs="*", default=["png", "apng", "bmp", "gif", "ico", "cur", "jpg", "jpeg", "jfif", "pjp", "pjpeg", "svg", "tif", "tiff", "webp", "xbm", "3gp", "aac", "flac", "mpg", "mpeg", "mp3", "mp4", "m4a", "m4v", "m4p", "oga", "ogg", "ogv", "mov", "wav", "webm", "eot", "woff", "woff2", "ttf", "otf", "css", "pdf", "zip", "avif", "json", "js"], help="File extensions to exclude.")
    parser.add_argument("--workers", type=int, default=2, help="Number of parallel workers (default: 2).")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between page visits in seconds (default: 1.0).")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, save_output_on_exit)
    crawl_and_capture_requests(
        args.target,
        args.output,
        args.depth,
        args.exclude,
        args.auth,
        args.login_url,
        args.username,
        args.password,
        args.workers,
        args.delay
    )

if __name__ == "__main__":
    main()
