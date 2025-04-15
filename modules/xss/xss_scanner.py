#!/usr/bin/env python3
"""
XSS (Cross-Site Scripting) Scanner module - Reflected XSS only
"""

import time
import re #  Dùng để tìm kiếm mẫu (pattern matching) trong chuỗi, rất hữu ích để xác định xem payload có xuất hiện trong response theo cách nào đó hay không
import urllib.parse
import uuid # Dùng để tạo một ID duy nhất (unique identifier) cho các payload dùng trong blind XSS, giúp phân biệt và theo dõi các lần test.
from bs4 import BeautifulSoup

from ..common.url_parser import URLParser
from ..common.request_handler import RequestHandler
from ..common.post_data_handler import PostDataHandler
from ..common.utils import Output
from .payload_generator import XSSPayloadGenerator


class XSSScanner:
    def __init__(self, urls=None, url=None, method="GET", data=None,
                 headers=None, timeout=10, delay=0,
                 user_agent=None, cookies=None, proxy=None,
                 callback_url=None, injection_types=None, verbose=False, no_color=False, verify_ssl=False):
       # user-agent : Xác định thông tin trình duyệt (User-Agent) được gửi trong header của request, giả lập trình duyệt
       # callback dùng blind xss , ở đây k dùng đến
       # verify_ssl để tắt cái kiểm tra chứng chỉ khi gửi reuqest nếu k hợp lệ
        self.urls = urls or []# urls or [] đảm bảo rằng nếu tham số urls không được cung cấp (hoặc là None), thì self.urls sẽ là một danh sách rỗng thay vì None, tránh lỗi khi duyệt danh sách sau này.
        if url and url not in self.urls:# nếu có url riêng và k có trong urls thì cho vào 
            self.urls.append(url)

        self.method = method.upper()
        self.data = data # đây là cái lấy từ option -d ra, 
        self.headers = headers or {}
        self.timeout = timeout
        self.delay = delay
        self.callback_url = callback_url
        self.verbose = verbose
        self.no_color = no_color

        # Only support reflected XSS now
        self.injection_types = ['reflected']

        # Initialize common modules
        self.url_parser = URLParser()
        self.request_handler = RequestHandler(
            timeout=timeout,
            user_agent=user_agent,
            cookies=cookies,
            headers=self.headers,
            proxy=proxy,
            delay=delay,
            verify_ssl=verify_ssl
        )

        self.post_data_handler = PostDataHandler()
        self.payload_generator = XSSPayloadGenerator()

        # Output formatting
        self.output = Output(no_color=no_color)

        # Results storage
        self.vulnerabilities = []
        self.scan_results = {}
        self.failed_urls = []

        # Generate unique ID for blind XSS testing
        self.unique_id = str(uuid.uuid4())[:8]#Tạo ID duy nhất (8 ký tự đầu của UUID)

    def scan(self):
     
        if not self.urls:
            return {'vulnerabilities': [], 'scan_info': {'urls_scanned': 0}}

        results = {
            'scan_info': {
                'start_time': time.time(),
                'urls_scanned': 0,
                'params_tested': 0,
                'payloads_tested': 0
            },
            'vulnerabilities': []
        }

        # Get payloads
        reflected_payloads = self.payload_generator.get_reflected_payloads()

       
       

        output = Output(no_color=self.no_color)

        # For each URL
        for url in self.urls:
            try:
                output.print_info(f"Scanning {url} for XSS vulnerabilities")

                # Parse URL to extract parameters
                parsed_url = self.url_parser.parse(url)
                parameters = parsed_url['parameters'] # parameters = {'q': 'test', 'page': '1'}

                # # cái POST này chưa dùng đến vì chưa code thiết kế gửi POST
                # post_params = {}
                # if self.method == "POST" and self.data:
                #     try:
                #         post_params = self.post_data_handler.parse_post_data(self.data)[
                #             'parameters']
                        
                #         # post_params = {
                #         #     'username': 'admin',
                #         #     'password': '123456',
                #         #     'token': 'abc123'
                #         # }
                #     except Exception as e:
                #         output.print_error(
                #             f"Error parsing POST data: {str(e)}")

                # Combine parameters from URL and POST data
                # all_params = {**parameters, **post_params} #  {'user': 'admin', 'id': '123', 'token': 'xyz456'}

                # if not all_params:
                #     output.print_warning(f"No parameters found in {url}")
                #     continue

                # output.print_info(
                #     f"Testing {len(all_params)} parameter(s) for XSS")

                # lấy response khi chưa gửi payload thôi
                if self.method == "GET":
                    baseline_response = self.request_handler.send_request(url)
                else:  # POST
                    baseline_response = self.request_handler.send_request(
                        url, method="POST", data=self.data)

                if not baseline_response:
                    output.print_error(
                        f"Failed to get baseline response for {url}")
                    continue

                # Track parameters tested
                results['scan_info']['params_tested'] += len(parameters) #  là một biến đếm số lượng tham số đã được kiểm tra trong quá trình quét.

                # For each parameter, test for XSS
                for param_name, param_value in parameters.items():
                    output.print_info(f"Testing parameter: {param_name}")

                    # Test for reflected XSS
                    self._scan_reflected_xss(
                        url, param_name, reflected_payloads, baseline_response)

                results['scan_info']['urls_scanned'] += 1

            except Exception as e:
                output.print_error(f"Error scanning {url}: {str(e)}")

            # Add delay between URLs if specified
            if self.delay > 0:
                time.sleep(self.delay)

        # Calculate scan duration
        results['scan_info']['end_time'] = time.time()#  Lưu thời gian kết thúc của quá trình quét vào end_time.
        results['scan_info']['duration'] = results['scan_info']['end_time'] - \
            results['scan_info']['start_time'] # dấu \ là để cho xuống dòng thôi,  Tính tổng thời gian quét bằng cách lấy thời gian kết thúc trừ đi thời gian bắt đầu.
        results['vulnerabilities'] = self.get_vulnerabilities()

        output.print_success(
            f"XSS scan completed in {results['scan_info']['duration']:.2f} seconds")# .2f lấy 2 số sau dấu .
        output.print_info(
            f"Found {len(results['vulnerabilities'])} XSS vulnerabilities")

        return results

    def _scan_reflected_xss(self, url, param_name, payloads, baseline_response):
  
        output = Output(no_color=self.no_color)
        output.print_info(
            f"Testing parameter '{param_name}' for reflected XSS")

        
        original_value = ""
        parsed_url = self.url_parser.parse(url)
    #      'parameters': {
    #     'q': 'test',
    #     'page': '1',
    #     'filter': 'new',
    #     'empty': ''
    # } cái 'parameters nó dạng này do caí class URLParser với hàm parse
        if param_name in parsed_url['parameters']: # kiểm tra xem cái param_name truyền vào có đúng là thuộc url không
            original_value = parsed_url['parameters'][param_name]
            in_url = True
        elif self.method == "POST" and self.data: # nếu là POST và truyền các tham số của form vào data thì 
            # Check if parameter is in POST data
            post_params = self.post_data_handler.parse_post_data(self.data)[ # trích xuất tham số từ body ra 
                'parameters']
            if param_name in post_params: # nếu cái param_name truyền vào giống cái trong body thì lấy giá trị của cái value
                original_value = post_params[param_name]
                in_url = False
            else:
                output.print_warning(
                    f"Parameter '{param_name}' not found in request")
                return
        else:
            output.print_warning(f"Parameter '{param_name}' not found in URL")
            return

        # Test each payload
        for payload in payloads:
            try:
                # Generate test URL or POST data with payload
                if in_url:
                    test_url = self.url_parser.inject_payload(
                        url, param_name, payload)
                    response = self.request_handler.send_request(test_url)
                else:
                    # Inject payload into POST data
                    modified_data = self.data.replace(
                        f"{param_name}={original_value}", f"{param_name}={payload}")# thay value bằng payload
                    response = self.request_handler.send_request(
                        url, method="POST", data=modified_data)

                if not response:
                    continue

                # Check if payload is reflected in response
                is_vulnerable, evidence = self._detect_reflected_xss(
                    response.text, payload)

                if is_vulnerable:
                    vuln = {
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': evidence,
                        'type': 'Reflected XSS'
                    }

                    self.vulnerabilities.append(vuln)

                    output.print_success(
                        f"Reflected XSS found in {url}, parameter: {param_name}")
                    output.print_success(f"Payload: {payload}")
                    output.print_success(f"Evidence: {evidence}")

                    # Break after finding vulnerability for parameter
                    break

            except Exception as e:
                output.print_error(f"Error testing payload: {str(e)}")

    def _detect_reflected_xss(self, response_text, payload):
    
        evidence = ""

        # kiểm tra xem payload có trong response không
        if payload in response_text:
            # Look for the context of reflection
            index = response_text.find(payload)
            start = max(0, index - 40)
            end = min(len(response_text), index + len(payload) + 40)
            evidence = response_text[start:end] # lấy 40 kí tự trước và sau vị trí phát hiện làm bằng chứng

            # Kiểm tra payload có nằm trong thẻ <script> hay không
            if '<script' in response_text[:index] and '</script>' in response_text[index+len(payload):]:
                return True, evidence
            # response_text[:index] có nghĩa là lấy từ đầu chuỗi (0) đến index - 1
            # response_text[index+len(payload):] có nghĩa là lấy phần chuỗi từ vị trí index + len(payload) đến hết
            # Nếu payload xuất hiện bên trong các thuộc tính nguy hiểm như src, href, onerror, onload, thì có thể khi người dùng truy cập trang, mã JavaScript độc hại sẽ được kích hoạt.
            if re.search(r'<[^>]+(src|href|onerror|onload)\s*=\s*[\'"]', response_text[:index]):
                return True, evidence
            #  <	Bắt đầu một thẻ HTML.
            # [^>]+	Bất kỳ ký tự nào không phải >, tức là nội dung của thẻ.
            # `(src	href
            # \s*=\s*	Dấu = với khoảng trắng tùy chọn trước/sau.
            # [\'"]	Giá trị thuộc tính phải bắt đầu bằng dấu nháy đơn (') hoặc nháy kép (").
            # Kiểm tra payload có chứa các sự kiện nguy hiểm không?
            # <img src="nonexistent.jpg" onerror="alert('XSS')">

            if '<img' in payload and 'onerror' in payload:
                return True, evidence

            # Check for script tags
            if '<script' in payload and '<script' in response_text:
                return True, evidence

            # For other contexts, just report as potential XSS
            return True, evidence

        # kiểm tra xem payload có bị mã hóa url encode không,  sợ trình duyệt nó decode trước khi render bằng innerHTML
        encoded_payload = urllib.parse.quote(payload)
        if encoded_payload != payload and encoded_payload in response_text:
            index = response_text.find(encoded_payload)
            start = max(0, index - 40)
            end = min(len(response_text), index + len(encoded_payload) + 40)
            evidence = response_text[start:end]
            return True, evidence

        # kiểm tra xem có bị html encode không, sợ trình duyệt nó decode trước khi render bằng innerHTML
        entity_payload = payload.replace('<', '&lt;').replace('>', '&gt;') #  thay thế (replace) các ký tự < và > bằng các HTML entity tương ứng
        if entity_payload != payload and entity_payload in response_text:
            index = response_text.find(entity_payload)
            start = max(0, index - 40)
            end = min(len(response_text), index + len(entity_payload) + 40)
            evidence = response_text[start:end]
            return True, evidence

        return False, evidence

    def _is_valid_url(self, url):
        """Check if URL is valid"""
        try:
            parsed = urllib.parse.urlparse(url)
            return all([parsed.scheme, parsed.netloc])
        except Exception:
            return False

    def get_results(self):
        """Get scan results"""
        return self.scan_results# trả về tổng kết kết quả quét (có thể bao gồm các thông tin chi tiết về quá trình quét, thời gian, số lượng URL đã quét, v.v.).

    def get_vulnerabilities(self):
        """Get discovered vulnerabilities"""
        return self.vulnerabilities # chỉ trả về danh sách các lỗ hổng XSS đã phát hiện.
