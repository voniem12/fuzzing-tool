#!/usr/bin/env python3
"""
Request Handler module for the Web Security Fuzzer
"""

import time
import requests
from requests.exceptions import RequestException
from urllib.parse import urlparse
import urllib3


class RequestHandler:
    def __init__(self, timeout=100, user_agent=None, cookies=None, proxy=None, delay=0, headers=None, verify_ssl=False):
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent or "WebSecurityFuzzer/2.0"

        # Kiểm tra nếu cookies đã là dict thì sử dụng trực tiếp
        if isinstance(cookies, dict):
            self.cookies = cookies
        else:
            self.cookies = self._parse_cookies(cookies) if cookies else {}

        self.proxies = self._setup_proxy(proxy) if proxy else {}
        self.headers = headers or {}
        self.verify_ssl = verify_ssl

        # Tắt cảnh báo SSL khi không xác minh chứng chỉ
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Configure requests session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent
        })

        # Add custom headers if provided
        if self.headers:
            self.session.headers.update(self.headers)

        if self.cookies:
            self.session.cookies.update(self.cookies)

    def _parse_cookies(self, cookies_str):
        """
        Parse cookies string into a dictionary

        Args:
            cookies_str (str): Cookies in format "name1=value1; name2=value2"

        Returns:
            dict: Parsed cookies
        """
        try:
            cookies = {}
            if cookies_str: # cookies_str = "session_id=12345; user=admin; theme=dark"
                for cookie in cookies_str.split(';'): # ['session_id=12345', ' user=admin', ' theme=dark']

                    if '=' in cookie:
                        name, value = cookie.strip().split('=', 1)
                        cookies[name] = value
            return cookies # {'session_id': '12345', 'user': 'admin', 'theme': 'dark'}

        except Exception as e:
            print(f"[!] Error parsing cookies: {e}")
            return {}

    def _setup_proxy(self, proxy): # chưa hiểu để làm gì
        """
        Setup proxy configuration

        Args:
            proxy (str): Proxy string in format "http://host:port"

        Returns:
            dict: Proxy configuration for requests
        """
        try:
            proxies = {
                'http': proxy,
                'https': proxy
            }
            return proxies
        except Exception as e:
            print(f"[!] Error setting up proxy: {e}")
            return {}

    def send_request(self, url, method="GET", data=None, headers=None, allow_redirects=True):
        """
        Send HTTP request to the specified URL

        Args:
            url (str): Target URL
            method (str, optional): HTTP method. Defaults to "GET".
            data (dict, optional): POST data. Defaults to None.
            headers (dict, optional): Additional headers. Defaults to None.
            allow_redirects (bool, optional): Whether to follow redirects. Defaults to True.

        Returns:
            requests.Response or None: Response object or None on failure
        """
        try:
            # Apply delay if specified
            if self.delay > 0:
                time.sleep(self.delay)

            # Set up custom headers if provided
            request_headers = {}
            if headers:
                request_headers.update(headers)

            # chọn phương thức để gửi thôi
            if method.upper() == "GET":
                response = self.session.get( # gửi 1 request đi
                    url,
                    headers=request_headers,
                    proxies=self.proxies,
                    timeout=self.timeout,
                    verify=self.verify_ssl,  # Sử dụng cấu hình xác minh SSL
                    allow_redirects=allow_redirects
                )
            elif method.upper() == "POST":
                response = self.session.post(
                    url,
                    data=data,
                    headers=request_headers,
                    proxies=self.proxies,
                    timeout=self.timeout,
                    verify=self.verify_ssl,  # Sử dụng cấu hình xác minh SSL
                    allow_redirects=allow_redirects
                )
            elif method.upper() == "HEAD":
                response = self.session.head(
                    url,
                    headers=request_headers,
                    proxies=self.proxies,
                    timeout=self.timeout,
                    verify=self.verify_ssl,  # Sử dụng cấu hình xác minh SSL
                    allow_redirects=allow_redirects
                )
            else:
                print(f"[!] Unsupported HTTP method: {method}")
                return None

            return response

        except RequestException as e:
            print(f"[!] Request failed for {url}: {e}")
            return None
        except Exception as e:
            print(f"[!] Error sending request to {url}: {e}")
            return None

    def check_connection(self, url): # check xem có kết nối k thôi
        """
        Check if the target is reachable

        Args:
            url (str): Target URL

        Returns:
            bool: True if target is reachable, False otherwise
        """
        try:
            response = self.send_request(url)
            return response is not None and response.status_code < 500
        except Exception:
            return False

    def get_links_from_html(self, html_content):# cái này k dùng đến
        """
        Extract links from HTML content using simple regex

        Args:
            html_content (str): HTML content

        Returns:
            list: List of extracted links
        """
        from bs4 import BeautifulSoup

        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            links = []

            # Get all <a> tags
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    links.append(href)

            # Get all <form> tags
            for form in soup.find_all('form'):
                action = form.get('action')
                if action:
                    links.append(action)

            # Get all <script> tags with src
            for script in soup.find_all('script'):
                src = script.get('src')
                if src:
                    links.append(src)

            # Get all <link> tags
            for link in soup.find_all('link'):
                href = link.get('href')
                if href:
                    links.append(href)

            # Get all <img> tags
            for img in soup.find_all('img'):
                src = img.get('src')
                if src:
                    links.append(src)

            # Remove duplicates
            return list(set(links))

        except Exception as e:
            print(f"[!] Error extracting links: {e}")
            return []

    def normalize_url(self, base_url, link):# không dùng 
        """ 
        Normalize a URL by resolving relative URLs

        Args:
            base_url (str): Base URL
            link (str): Link to normalize

        Returns:
            str: Normalized URL
        """
        try:
            from urllib.parse import urljoin
            return urljoin(base_url, link)
        except Exception as e:
            print(f"[!] Error normalizing URL: {e}")
            return link
