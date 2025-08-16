import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import re
import json
import time
import random
import threading
from queue import Queue
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from stem import Signal
from stem.control import Controller
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import js2py  # For parsing JavaScript to discover APIs
from readability import Document  # For extracting clean article content
import logging
from logging.handlers import RotatingFileHandler

# OPSEC: Mask logs (disable in debug mode)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
handler = RotatingFileHandler('paywall_bypass.log', maxBytes=5*1024*1024, backupCount=3)
logger.addHandler(handler)

class PaywallBypass:
    def __init__(self, target_url, proxies=None, use_tor=False, headless=True, site_specific=True, captcha_api_key=None, debug=False):
        self.target_url = target_url
        self.proxies = proxies if isinstance(proxies, list) else [proxies] if proxies else None
        self.current_proxy_idx = 0
        self.use_tor = use_tor
        self.headless = headless
        self.site_specific = site_specific
        self.captcha_api_key = captcha_api_key
        self.ua = UserAgent()
        self.tor_controller = None
        self.driver = None
        self.session = self._create_session()
        if debug:
            logger.setLevel(logging.DEBUG)
        self._configure_session()
        self.site = self._detect_site()

    def _detect_site(self):
        """Detect popular paywalled sites for tailored bypasses."""
        if 'nytimes.com' in self.target_url:
            return 'nyt'
        elif 'wsj.com' in self.target_url:
            return 'wsj'
        return None

    def _create_session(self):
        """Create a new requests session for thread-safety."""
        return requests.Session()

    def _configure_session(self):
        """Configure HTTP session with retries and proxies."""
        retry_strategy = Retry(
            total=5,  # Increased retries
            backoff_factor=2,  # Exponential backoff
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self._update_proxy()

    def _update_proxy(self):
        """Update session proxy, rotating if list provided."""
        if self.proxies:
            proxy = self.proxies[self.current_proxy_idx % len(self.proxies)]
            self.session.proxies.update(proxy)
            self.current_proxy_idx += 1
        elif self.use_tor:
            self._init_tor()

    def _init_tor(self):
        """Initialize Tor proxy and controller."""
        self.session.proxies = {
            'http': 'socks5://127.0.0.1:9050',
            'https': 'socks5://127.0.0.1:9050'
        }
        try:
            self.tor_controller = Controller.from_port(port=9051)
            self.tor_controller.authenticate()
        except Exception as e:
            logger.error(f"Tor controller failed: {e}")

    def _rotate_tor_ip(self):
        """Rotate Tor IP to avoid rate limits."""
        if self.tor_controller:
            try:
                self.tor_controller.signal(Signal.NEWNYM)
                time.sleep(random.uniform(3, 7))  # Randomized wait
            except Exception as e:
                logger.error(f"Tor IP rotation failed: {e}")

    def _get_headers(self):
        """Generate dynamic headers with spoofed User-Agent and Referer."""
        headers = {
            "User-Agent": self.ua.random,
            "Referer": random.choice(["https://www.google.com", "https://www.facebook.com", "https://t.co"]),
            "Accept-Language": "en-US,en;q=0.9",
        }
        if self.site == 'nyt':
            headers["X-Requested-With"] = "XMLHttpRequest"  # Site-specific
        return headers

    def _discover_api_endpoints(self, html):
        """Enhanced: Parse HTML/JS to find API endpoints using regex, BS4, and JS execution."""
        soup = BeautifulSoup(html, "html.parser")
        endpoints = set()

        # Find in <script> tags (enhanced regex for GraphQL/REST)
        for script in soup.find_all("script"):
            if script.src and re.search(r'(api|graphql|v\d)', script.src):
                endpoints.add(script.src)
            elif script.string:
                # Regex matches
                matches = re.findall(r'["\'](https?://[^"\']+/(api|graphql|v?\d?)/[\w/-]+)["\']', script.string)
                endpoints.update(matches)
                # Execute JS to extract dynamic vars
                try:
                    context = js2py.EvalJs()
                    context.execute(script.string)
                    if 'apiUrl' in context:
                        endpoints.add(context.apiUrl)
                except Exception as e:
                    logger.debug(f"JS parsing failed: {e}")

        # Find in <a> and <link> tags
        for tag in soup.find_all(["a", "link"], href=True):
            if re.search(r'(api|graphql)', tag["href"]):
                endpoints.add(tag["href"])

        return endpoints

    def _handle_captcha(self, html):
        """Detect CAPTCHA and solve using API or headless browser."""
        if "captcha" in html.lower() or "recaptcha" in html.lower():
            logger.warning("CAPTCHA detected.")
            if self.captcha_api_key:
                # Integrate 2Captcha (example; replace with actual API call)
                try:
                    # Placeholder: Send to 2Captcha API
                    logger.info("Sending CAPTCHA to solver...")
                    # solver_response = requests.post('http://2captcha.com/in.php', data={'key': self.captcha_api_key, 'method': 'userrecaptcha', 'googlekey': 'sitekey_from_html'})
                    # Assume solved captcha token
                    solved_token = "solved_token_placeholder"
                    return solved_token  # Use in subsequent request
                except Exception as e:
                    logger.error(f"CAPTCHA solver failed: {e}")
            # Fallback to headless
            logger.info("Falling back to headless browser...")
            if not self.driver:
                self._init_headless_browser()
            try:
                self.driver.get(self.target_url)
                WebDriverWait(self.driver, 15).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
                return self.driver.page_source
            except Exception as e:
                logger.error(f"CAPTCHA bypass failed: {e}")
        return None

    def _init_headless_browser(self):
        """Initialize headless Chrome with spoofing for CAPTCHA fallback."""
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument(f"user-agent={self.ua.random}")
        options.add_argument("window-size=1920,1080")  # Mimic real screen
        self.driver = webdriver.Chrome(options=options)

    def _extract_content(self, html):
        """Extract clean article content using readability."""
        if not html:
            return None
        doc = Document(html)
        return doc.summary()  # Returns clean HTML; can be further processed to text

    def bypass_via_headers(self):
        """Bypass paywall by spoofing headers."""
        time.sleep(random.uniform(1, 5))  # Rate limit
        try:
            response = self.session.get(self.target_url, headers=self._get_headers(), timeout=10)
            if response.status_code == 200:
                captcha_result = self._handle_captcha(response.text)
                content = captcha_result or response.text
                if "paywall" not in content.lower():
                    logger.info("[+] Paywall bypassed via header spoofing!")
                    return self._extract_content(content)
            self._rotate_tor_ip() if self.use_tor else self._update_proxy()
            return None
        except Exception as e:
            logger.error(f"Header spoofing failed: {e}")
            return None

    def bypass_via_api(self, api_endpoint=None):
        """Bypass paywall by directly accessing API endpoints."""
        time.sleep(random.uniform(1, 5))
        if not api_endpoint:
            initial_response = self.session.get(self.target_url, headers=self._get_headers())
            api_endpoints = self._discover_api_endpoints(initial_response.text)
            if not api_endpoints:
                logger.warning("No API endpoints discovered.")
                return None
            api_endpoint = random.choice(list(api_endpoints))

        try:
            response = self.session.get(api_endpoint, headers=self._get_headers())
            if response.status_code == 200:
                logger.info(f"[+] Paywall bypassed via API endpoint: {api_endpoint}")
                data = response.json() if "application/json" in response.headers.get("content-type", "") else response.text
                return json.dumps(data) if isinstance(data, dict) else data  # Normalize to string
            return None
        except Exception as e:
            logger.error(f"API access failed: {e}")
            return None

    def bypass_via_cookies(self, cookie_updates=None):
        """Bypass paywall by modifying/deleting cookies."""
        time.sleep(random.uniform(1, 5))
        if not cookie_updates:
            cookie_updates = {
                "free_views": None,
                "paywall_shown": "false",
                "subscription": "premium"
            }
            if self.site == 'nyt':
                cookie_updates["nyt-purr"] = "premium"  # Site-specific

        try:
            for name, value in cookie_updates.items():
                if value is None:
                    self.session.cookies.pop(name, None)
                else:
                    self.session.cookies.set(name, value, domain=self.target_url.split('//')[1].split('/')[0])

            response = self.session.get(self.target_url, headers=self._get_headers())
            if response.status_code == 200 and "paywall" not in response.text.lower():
                logger.info("[+] Paywall bypassed via cookie tampering!")
                return self._extract_content(response.text)
            return None
        except Exception as e:
            logger.error(f"Cookie tampering failed: {e}")
            return None

    def bypass_via_archive(self):
        """Bypass via archive services (Wayback Machine or Archive.today)."""
        time.sleep(random.uniform(1, 5))
        archives = [
            f"https://web.archive.org/web/*/{self.target_url}",
            f"https://archive.today/?run=1&url={self.target_url}"
        ]
        for archive_url in archives:
            try:
                response = self.session.get(archive_url, headers=self._get_headers())
                if response.status_code == 200 and "paywall" not in response.text.lower():
                    logger.info(f"[+] Paywall bypassed via archive: {archive_url}")
                    return self._extract_content(response.text)
            except Exception as e:
                logger.error(f"Archive bypass failed: {e}")
        return None

    def bypass_via_cache(self):
        """Bypass via Google Cache."""
        time.sleep(random.uniform(1, 5))
        cache_url = f"http://webcache.googleusercontent.com/search?q=cache:{self.target_url}"
        try:
            response = self.session.get(cache_url, headers=self._get_headers())
            if response.status_code == 200:
                logger.info("[+] Paywall bypassed via Google Cache!")
                return self._extract_content(response.text)
            return None
        except Exception as e:
            logger.error(f"Cache bypass failed: {e}")
            return None

    def execute_all_methods(self):
        """Execute all bypass methods with multi-threading."""
        results = {}
        threads = []
        methods = [
            ("headers", self.bypass_via_headers),
            ("api", self.bypass_via_api),
            ("cookies", self.bypass_via_cookies),
            ("archive", self.bypass_via_archive),
            ("cache", self.bypass_via_cache),
        ]

        def worker(method_name, method_func, result_queue, session):
            local_session = session  # Thread-local session
            result = method_func()
            result_queue.put((method_name, result))

        result_queue = Queue()
        for method_name, method_func in methods:
            thread = threading.Thread(
                target=worker,
                args=(method_name, method_func, result_queue, self._create_session())
            )
            threads.append(thread)
            thread.start()
            time.sleep(random.uniform(0.5, 2))  # Stagger threads

        for thread in threads:
            thread.join()

        while not result_queue.empty():
            method_name, result = result_queue.get()
            results[method_name] = result

        return results

    def __del__(self):
        """Cleanup resources."""
        if self.driver:
            self.driver.quit()
        if self.tor_controller:
            self.tor_controller.close()

# Example usage
if __name__ == "__main__":
    target_url = "https://paywalled-site.com/article"
    
    # Optional: List of proxies for rotation
    proxies = [
        {"http": "http://proxy1:port", "https": "http://proxy1:port"},
        {"http": "http://proxy2:port", "https": "http://proxy2:port"}
    ]
    use_tor = False  # Set to True if using Tor
    captcha_api_key = "your_2captcha_key"  # Optional

    bypass = PaywallBypass(target_url, proxies=proxies, use_tor=use_tor, headless=True, site_specific=True, captcha_api_key=captcha_api_key, debug=True)
    results = bypass.execute_all_methods()

    # Save results (TXT and JSON)
    with open("paywall_bypass_results.txt", "w") as f, open("paywall_bypass_results.json", "w") as jf:
        json_data = {}
        for method, content in results.items():
            if content:
                f.write(f"\n=== {method.upper()} ===\n{content}\n")
                json_data[method] = content
        json.dump(json_data, jf, indent=4)
    logger.info("Results saved to 'paywall_bypass_results.txt' and '.json'.")