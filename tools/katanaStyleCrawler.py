import time
import json
import logging
import re
import random
import string
import secrets
import datetime
from urllib.parse import urljoin, urlparse
from seleniumwire import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import (
    WebDriverException,
    TimeoutException,
    StaleElementReferenceException,
    NoSuchElementException,
)
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
import argparse
import signal
import sys

# === LOGGING ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
requests_data = []

# === DRIVER ===
def initialize_driver():
    chrome_options = Options()
    # chrome_options.add_argument("--headless")
    chrome_options.add_argument('--ignore-certificate-errors')
    chrome_options.add_argument('--ignore-ssl-errors')
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--window-size=1920x1080")
    return webdriver.Chrome(options=chrome_options)

# === UTILS ===
def is_in_scope(base_url, url):
    return urlparse(base_url).netloc == urlparse(url).netloc

def safe_get(driver, url, retries=3, delay=2):
    for attempt in range(retries):
        try:
            driver.get(url)
            WebDriverWait(driver, 120).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            logging.info(f"Loaded: {url}")
            return True
        except (WebDriverException, TimeoutException) as e:
            logging.warning(f"Retry {attempt + 1}/{retries} | {e}")
            time.sleep(random.uniform(delay, delay + 2))
    logging.error(f"Failed: {url}")
    return False

# === LOGIN ===
def login(driver, login_url, username, password):
    safe_get(driver, login_url)
    try:
        username_field = WebDriverWait(driver, 30).until(
            EC.visibility_of_element_located((By.CSS_SELECTOR, "#email"))
        )
        username_field.clear()
        username_field.send_keys(username)

        password_field = driver.find_element(By.CSS_SELECTOR, "#password")
        password_field.clear()
        password_field.send_keys(password)
        password_field.send_keys(Keys.RETURN)

        WebDriverWait(driver, 30).until(EC.url_changes(login_url))
        logging.info("Login successful")
    except Exception as e:
        logging.error(f"Login failed: {e}")
        raise

# === FORM FILL ===
def fill_random_inputs_and_submit(driver):
    try:
        for el in driver.find_elements(By.TAG_NAME, "input"):
            t = (el.get_attribute("type") or "").lower()
            if t in ["submit", "button", "reset", "hidden"]:
                continue
            val = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
            try:
                el.clear()
                el.send_keys(val)
                logging.info(f"Filled input: {val}")
            except:
                pass

        for el in driver.find_elements(By.TAG_NAME, "textarea"):
            val = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
            try:
                el.clear()
                el.send_keys(val)
                logging.info(f"Filled textarea: {val}")
            except:
                pass

        for xpath in ["//input[@type='submit']", "//button"]:
            for btn in driver.find_elements(By.XPATH, xpath):
                try:
                    if btn.is_displayed() and btn.is_enabled():
                        # btn.click()
                        logging.info(f"Clicked button: {btn.text or 'No text'}")
                        return
                except:
                    continue
    except Exception as e:
        logging.error(f"Form error: {e}")

# === TAG/ATTRIBUTE ===
def _guess_tag_attribute(request):
    url = request.url.lower()
    method = request.method.upper()
    if "xhr" in getattr(request, "type", "").lower() or "fetch" in url:
        return "script", "src"
    if method == "POST":
        return "form", "action"
    if method in ("GET", "HEAD"):
        if url.endswith(('.css', '.js', '.png', '.jpg', '.gif', '.svg', '.woff', '.woff2', '.pdf')):
            return "link", "href"
        return "a", "href"
    return "", ""

# === CAPTURE REQUESTS ===
def capture_requests_for_page(driver, base_url, current_url, current_depth, requests_data, visited_requests, exclude_pattern):
    for request in driver.requests:
        if not request.response:
            continue
        if exclude_pattern.search(request.url) or not is_in_scope(base_url, request.url):
            continue

        key = (request.url, request.method)
        if key in visited_requests:
            continue

        visited_requests.add(key)
        tag, attr = _guess_tag_attribute(request)

        # Decode body safely
        body = None
        if request.body:
            try:
                body = request.body.decode('utf-8', errors='replace')
            except:
                body = ""

        # ISO-8601 UTC timestamp
        ts = time.time()
        ts_iso = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()

        requests_data.append({
            "url": request.url,
            "method": request.method,
            "status_code": request.response.status_code,
            "headers": dict(request.headers),
            "response_headers": dict(request.response.headers),
            "body": body,
            "source": current_url,
            "tag": tag,
            "attribute": attr,
            "depth": current_depth + 1,
            "timestamp": ts,
            "timestamp_iso": ts_iso,
        })

# === WRITE KATANA-STYLE JSONL ===
def _write_katana_style_jsonl(filepath: str):
    static_exts = [
        ".css",".js",".png",".jpg",".jpeg",".gif",
        ".svg",".woff",".woff2",".pdf",".ico"
    ]
    with open(filepath, "w", encoding="utf-8") as f:
        for entry in requests_data:
            if any(entry["url"].lower().endswith(e) for e in static_exts):
                continue

            # Raw request
            path = urlparse(entry["url"]).path or "/"
            raw_req_lines = [f"{entry['method']} {path} HTTP/1.1"]
            for k, v in entry["headers"].items():
                raw_req_lines.append(f"{k}: {v}")
            raw_req = "\r\n".join(raw_req_lines) + "\r\n\r\n"

            # Raw response
            status_line = f"HTTP/1.1 {entry['status_code']} OK"
            raw_resp_headers = "\r\n".join(
                f"{k}: {v}" for k, v in entry["response_headers"].items()
            )
            body = entry["body"] or ""
            raw_resp = f"{status_line}\r\n{raw_resp_headers}\r\n\r\n{body}\r\n"

            obj = {
                "timestamp": entry["timestamp_iso"],
                "request": {
                    "method": entry["method"],
                    "endpoint": entry["url"],
                    "raw": raw_req,
                },
                "response": {
                    "status_code": entry["status_code"],
                    "headers": entry["response_headers"],
                    "body": body,
                    "content_length": len(body),
                    "raw": raw_resp,
                },
            }

            if entry.get("tag"):
                obj["request"]["tag"] = entry["tag"]
                obj["request"]["attribute"] = entry["attribute"]
                obj["request"]["source"] = entry["source"]

            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

# === MAIN CRAWLER ===
def crawl_and_capture_requests(base_url, output_file, max_depth, exclude_extensions, auth_required=False, login_url=None, username=None, password=None):
    driver = initialize_driver()
    visited_pages = set()
    to_visit = [(base_url, 0)]
    visited_requests = set()

    exclude_pattern = re.compile(rf"(?i)\.({'|'.join(map(re.escape, exclude_extensions))})(?:\?|#|$)", re.IGNORECASE)

    if auth_required:
        login(driver, login_url, username, password)

    try:
        while to_visit:
            url, depth = to_visit.pop(0)
            if url in visited_pages or depth > max_depth:
                continue

            if not safe_get(driver, url):
                continue

            visited_pages.add(url)
            logging.info(f"Crawled: {url} | Depth: {depth}")

            fill_random_inputs_and_submit(driver)
            capture_requests_for_page(driver, base_url, url, depth, requests_data, visited_requests, exclude_pattern)

            try:
                for a in driver.find_elements(By.TAG_NAME, "a"):
                    href = a.get_attribute("href")
                    if href and is_in_scope(base_url, href):
                        full = urljoin(url, href)
                        if full not in visited_pages:
                            to_visit.append((full, depth + 1))
            except StaleElementReferenceException:
                pass

        # === FINAL OUTPUT ===
        _write_katana_style_jsonl(output_file)

        count = sum(
            1 for e in requests_data
            if not any(e["url"].lower().endswith(x) for x in [
                ".css",".js",".png",".jpg",".gif",".svg",".woff",".woff2",".pdf",".ico"
            ])
        )
        logging.info(f"Saved {count} endpoints to {output_file}")

    finally:
        driver.quit()

# === GRACEFUL EXIT ===
def save_output_on_exit(sig, frame):
    logging.info("Ctrl+C – saving partial results …")
    _write_katana_style_jsonl("partial_katana.jsonl")
    logging.info("Partial file: partial_katana.jsonl")
    sys.exit(0)

# === CLI ===
def main():
    parser = argparse.ArgumentParser(description="Crawler → Katana-style JSONL (Nuclei-ready)")
    parser.add_argument("-t", "--target", required=True, help="Start URL")
    parser.add_argument("-o", "--output", required=True, help="Output JSONL")
    parser.add_argument("-d", "--depth", type=int, default=4, help="Max depth")
    parser.add_argument("-a", "--auth", action="store_true")
    parser.add_argument("-l", "--login-url")
    parser.add_argument("-u", "--username")
    parser.add_argument("-p", "--password")
    parser.add_argument("--exclude", nargs="*", default=[
        "png", "jpg", "jpeg", "gif", "svg", "css", "js", "pdf", "woff", "woff2", "ico"
    ])
    args = parser.parse_args()

    signal.signal(signal.SIGINT, save_output_on_exit)
    crawl_and_capture_requests(
        base_url=args.target,
        output_file=args.output,
        max_depth=args.depth,
        exclude_extensions=args.exclude,
        auth_required=args.auth,
        login_url=args.login_url,
        username=args.username,
        password=args.password
    )

if __name__ == "__main__":
    main()
