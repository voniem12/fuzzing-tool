#!/usr/bin/env python3
"""
SQL Injection Scanner module for the Web Security Fuzzer
With enhanced MySQL detection capabilities
"""

import time
import random
import urllib.parse
from datetime import datetime
import re # Thư viện re trong Python là Regular Expression (Biểu thức chính quy), dùng để tìm kiếm, khớp (match), thay thế, tách chuỗi, và kiểm tra định dạng của dữ liệu dựa trên mẫu (pattern)

# Import modules from the sql package
from modules.sql.payload_generator import SQLPayloadGenerator
from modules.sql.response_analyzer import ResponseAnalyzer
from modules.sql.mysql_payloads import (
    get_mysql_error_payloads,
    get_mysql_boolean_payloads,
    get_mysql_time_payloads,
    get_mysql_union_payloads
)

# Import common modules
from modules.common.request_handler import RequestHandler
from modules.common.utils import Output


class SQLScanner:
    """
    SQLScanner class for detecting SQL injection vulnerabilities in web applications.
    Enhanced with MySQL-specific testing capabilities.
    Supports error-based, boolean-based, time-based, and union-based injection testing.
    """

    def __init__(self, urls=None, url=None, method="GET", data=None, headers=None,
                 cookies=None, timeout=10, delay=0, user_agent=None, proxy=None,
                 injection_types=None, verbose=False, no_color=False, dbms="mysql", target_params=None, verify_ssl=True):
        """
        Initialize the SQL Scanner

        Args:
            urls (list): List of URLs to scan
            url (str): Single URL to scan
            method (str): HTTP method (GET or POST)
            data (str): POST data
            headers (dict): Custom HTTP headers
            cookies (dict): HTTP cookies
            timeout (int): Request timeout in seconds
            delay (int): Delay between requests in seconds
            user_agent (str): Custom User-Agent
            proxy (dict): Proxy configuration
            injection_types (list): List of injection types to test
            verbose (bool): Enable verbose output
            no_color (bool): Disable colored output
            dbms (str): Target database management system (default: mysql)
            target_params (list): Specific parameters to test (if None, test all)
            verify_ssl (bool): Whether to verify SSL certificates
        """
        self.urls = urls or []
        if url and url not in self.urls:# đảm bảo rằng url k rỗng và url k bị trùng
            self.urls.append(url)

        self.method = method.upper()
        self.data = data
        self.headers = headers or {}
        self.cookies = cookies
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent
        self.proxy = proxy
        self.verbose = verbose
        self.no_color = no_color
        self.dbms = dbms.lower()  # Target database type, default to MySQL
        self.target_params = target_params  # Specific parameters to test
        self.verify_ssl = verify_ssl

        # Default injection types if none specified
        self.injection_types = injection_types or [
            'error', 'boolean', 'time', 'union']# phòng th k truyền type thôi

        # Initialize request handler
        self.request_handler = RequestHandler(
            timeout=self.timeout,
            user_agent=self.user_agent,
            proxy=self.proxy,
            cookies=self.cookies,
            headers=self.headers,
            verify_ssl=self.verify_ssl
        )

        # Initialize payload generator
        self.payload_generator = SQLPayloadGenerator()

        # Initialize response analyzer
        self.response_analyzer = ResponseAnalyzer(verbose=self.verbose)

        # Initialize output handler
        self.output = Output(no_color=self.no_color)

        # Load MySQL-specific payloads
        self._load_mysql_payloads()

        # Results container
        self.results = {
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'targets': [],
            'vulnerabilities': []
        }

    def _load_mysql_payloads(self):
        """Load MySQL-specific payloads"""
        self.mysql_error_payloads = get_mysql_error_payloads()
        self.mysql_boolean_payloads = get_mysql_boolean_payloads()
        self.mysql_time_payloads = get_mysql_time_payloads()
        self.mysql_union_payloads = get_mysql_union_payloads()

    def scan(self):
        """
        Start SQL injection scanning process

        Returns:
            dict: Scan results
        """
        if not self.urls:
            self.output.error("No target URLs provided")
            return self.results

        for url in self.urls:
            try:
                self._scan_url(url)

                # Add delay between requests if specified
                if self.delay > 0:
                    time.sleep(self.delay)

            except Exception as e:
                self.output.error(f"Error scanning {url}: {str(e)}")

                # Add to results
                self.results['targets'].append({
                    'url': url,
                    'status': 'error',
                    'error': str(e)
                })

        return self.results

    def _scan_url(self, url):
        """
        Scan a single URL for SQL injection vulnerabilities

        Args:
            url (str): Target URL
        """
        self.output.info(f"Scanning {url} for MySQL injection vulnerabilities")

        # Extract URL parameters
        parsed_url = urllib.parse.urlparse(url)
        #         Hàm urlparse() sẽ trả về một đối tượng ParseResult gồm 6 thành phần:

        # scheme – Giao thức (http, https, ftp, v.v.)

        # netloc – Tên miền hoặc địa chỉ IP kèm cổng

        # path – Đường dẫn tài nguyên

        # params – Tham số (ít dùng, chủ yếu trong CGI)

        # query – Chuỗi truy vấn (sau dấu ?)

        # fragment – Đoạn fragment (sau dấu #, dùng trong HTML)


        # Add URL to targets
        target_info = {
            'url': url,
            'method': self.method,
            'parameters_tested': [],
            'vulnerabilities_found': 0,
            'status': 'scanning'
        }
        self.results['targets'].append(target_info)

        # For GET requests, extract parameters from URL
        if self.method == "GET":
            params = urllib.parse.parse_qs(parsed_url.query)
            if params:
                self._test_parameters(url, params, "GET")
            else:
                self.output.warning(f"No parameters found in URL: {url}")
                target_info['status'] = 'completed'

        # For POST requests, use provided data
        elif self.method == "POST":
            if not self.data:
                self.output.warning(f"No POST data provided for: {url}")
                target_info['status'] = 'completed'
                return

            # Parse POST data
            try:
                # Phân tích dữ liệu POST dạng application/x-www-form-urlencoded
                params = {}
                for param_pair in self.data.split('&'): # username=admin&password=123456
                    if '=' in param_pair:
                        name, value = param_pair.split('=', 1)
                        params[urllib.parse.unquote_plus(
                            name)] = urllib.parse.unquote_plus(value)# { "username": "admin", "password": "123456"}
                        # unquote dùng để thay dấu + bằng khoảng trắng
    
    

                if params:
                    self._test_parameters(url, params, "POST")
                else:
                    self.output.warning(f"No parameters found in POST data")
                    target_info['status'] = 'completed'
            except Exception as e:
                self.output.error(f"Error parsing POST data: {str(e)}")
                target_info['status'] = 'error'
                target_info['error'] = str(e)

        # Update target status
        target_info['status'] = 'completed'

    def _test_parameters(self, url, params, method):
        """
        Test each parameter for SQL injection vulnerabilities

        Args:
            url (str): Target URL
            params (dict): Parameters to test
            method (str): HTTP method (GET or POST)
        """
        # Filter parameters if target_params is specified
        if self.target_params:
            filtered_params = {}
            for param in self.target_params:
                if param in params:
                    filtered_params[param] = params[param]

            if not filtered_params:
                self.output.warning(
                    f"None of the specified parameters {', '.join(self.target_params)} found in request")
                return

            params = filtered_params
            self.output.info(
                f"Testing {len(params)} specified parameters for MySQL injection")
        else:
            self.output.info(
                f"Testing {len(params)} parameters for MySQL injection")

        # Get baseline response for comparison
        baseline_response = self._get_baseline_response(url, method)
        if not baseline_response:
            self.output.error("Failed to get baseline response")
            return

        # Get baseline timing for time-based detection
        baseline_time = baseline_response.elapsed.total_seconds() # đếm tổng số giây phản hồi thôi
        self.output.info(
            f"Baseline response time: {baseline_time:.2f} seconds")

        # Store total vulnerabilities found
        total_vulnerabilities = 0

        # Test each parameter
        for param_name, param_values in params.items():
            param_value = param_values[0] if isinstance( # nếu tham số có nhiều giá trị thì nó chỉ lấy cái đầu tiên thôi
                param_values, list) else param_values
            self.output.info(f"Testing parameter: {param_name}")

            # Add to parameters tested
            for target in self.results['targets']:
                if target['url'] == url:
                    if param_name not in target['parameters_tested']:
                        target['parameters_tested'].append(param_name)

            # Test for each injection type
            vulnerabilities = []

            # Cờ để kiểm tra xem đã tìm thấy lỗ hổng chưa
            vulnerability_found = False

            # Error-based injection
            if not vulnerability_found and 'error' not in self.injection_types:
                self.output.info(
                    "Skipping error-based testing (not in selected types)")
            elif not vulnerability_found:
                self.output.info("Testing for error-based MySQL injection")
                error_vuln = self._test_error_based(
                    url, param_name, params, method, baseline_response)
                if error_vuln:
                    vulnerabilities.append(error_vuln)
                    total_vulnerabilities += 1
                    vulnerability_found = True
                    self.output.success(
                        f"Error-based SQL injection found! Stopping further tests for this parameter.")

            # Boolean-based injection
            if not vulnerability_found and 'boolean' not in self.injection_types:
                self.output.info(
                    "Skipping boolean-based testing (not in selected types)")
            elif not vulnerability_found:
                self.output.info("Testing for boolean-based MySQL injection")
                boolean_vuln = self._test_boolean_based(
                    url, param_name, params, method, baseline_response)
                if boolean_vuln:
                    vulnerabilities.append(boolean_vuln)
                    total_vulnerabilities += 1
                    vulnerability_found = True
                    self.output.success(
                        f"Boolean-based SQL injection found! Stopping further tests for this parameter.")

            # Time-based injection
            if not vulnerability_found and 'time' not in self.injection_types:
                self.output.info(
                    "Skipping time-based testing (not in selected types)")
            elif not vulnerability_found:
                self.output.info("Testing for time-based MySQL injection")
                time_vuln = self._test_time_based(
                    url, param_name, params, method, baseline_response)
                if time_vuln:
                    vulnerabilities.append(time_vuln)
                    total_vulnerabilities += 1
                    vulnerability_found = True
                    self.output.success(
                        f"Time-based SQL injection found! Stopping further tests for this parameter.")

            # Union-based injection
            if not vulnerability_found and 'union' not in self.injection_types:
                self.output.info(
                    "Skipping union-based testing (not in selected types)")
            elif not vulnerability_found:
                self.output.info("Testing for union-based MySQL injection")
                union_vuln = self._test_union_based(
                    url, param_name, params, method, baseline_response)
                if union_vuln:
                    vulnerabilities.append(union_vuln)
                    total_vulnerabilities += 1
                    vulnerability_found = True
                    self.output.success(
                        f"Union-based SQL injection found! Stopping further tests for this parameter.")

            # Check if vulnerabilities were found for this parameter
            if vulnerabilities:
                self.output.success(
                    f"Found {len(vulnerabilities)} vulnerabilities in parameter: {param_name}")

                # Update vulnerability count in target info
                for target in self.results['targets']:
                    if target['url'] == url:
                        target['vulnerabilities_found'] += len(vulnerabilities)

        # Print summary
        if total_vulnerabilities > 0:
            self.output.success(
                f"Found {total_vulnerabilities} MySQL injection vulnerabilities in {url}")
        else:
            self.output.info(
                f"No MySQL injection vulnerabilities found in {url}")

    def _get_baseline_response(self, url, method):
        """
        Get baseline response for comparison

        Args:
            url (str): Target URL
            method (str): HTTP method

        Returns:
            requests.Response: Baseline response
        """
        try:
            if method == "GET":
                return self.request_handler.send_request(url, method)
            else:
                return self.request_handler.send_request(url, method, self.data)
        except Exception as e:
            self.output.error(f"Error getting baseline response: {str(e)}")
            return None

    def _test_error_based(self, url, param_name, params, method, baseline_response):
        """
        Test for error-based SQL injection

        Args:
            url (str): Target URL
            param_name (str): Parameter name to test
            params (dict): All parameters
            method (str): HTTP method
            baseline_response (requests.Response): Baseline response

        Returns:
            dict or None: Vulnerability details if found, None otherwise
        """
        self.output.info(
            f"Testing parameter '{param_name}' for error-based MySQL injection")

        # Use MySQL-specific error payloads
        payloads = self.mysql_error_payloads

        # For verbose output, show number of payloads
        if self.verbose:
            self.output.info(
                f"Testing with {len(payloads)} MySQL error-based payloads")

        for i, payload in enumerate(payloads): #  enumerate nó chỉ là in ra payload kèm theo vị trí của nó thôi
            # Clone parameters and modify the tested one
            modified_params = self._clone_and_modify_params( # Sao chép lại tham số từ params, thay payload vào giá trị của tham số
                params, param_name, payload)

            try:
                # Send request with modified parameters
                if method == "GET":
                    # Rebuild query string
                    query_string = '&'.join(# dấu & là để nối nhiều tham số vào thôi
                        [f"{k}={v}" for k, v in modified_params.items()]) # chỗ này là lấy các cặp key = value ra
                    # "username=admin&password=123456&role=user"

                    parsed_url = urllib.parse.urlparse(url)
                    # Replace query string
                    modified_url = urllib.parse.urlunparse(( # unparse để ghép lại thôi
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        query_string, # cái modify này nó thay query bằng cái query _string trên kia
                        parsed_url.fragment
                    ))

                    response = self.request_handler.send_request(
                        modified_url, method)
                else:
                    # Rebuild POST data
                    modified_data = '&'.join(
                        [f"{k}={v}" for k, v in modified_params.items()])
                    response = self.request_handler.send_request(
                        url, method, modified_data) #modified_data là để đính kèm dữ liệu vào body để gửi

                if not response:
                    continue

                # Analyze response for SQL errors
                result = self.response_analyzer.analyze(response, payload)

                if result['vulnerable'] and result['type'] == 'error-based':
                    # Found a vulnerability!
                    self.output.success(
                        f"Found error-based MySQL injection in parameter: {param_name}")
                    self.output.success(f"Payload: {payload}")

                    # Add vulnerability to results
                    vulnerability = {
                        'type': 'error-based',
                        'parameter': param_name,
                        'payload': payload,
                        'details': result['details']
                    }

                    if result['extracted_data']:
                        vulnerability['extracted_data'] = result['extracted_data']
                        self.output.success(
                            f"Extracted data: {result['extracted_data']}")

                    self._add_vulnerability(
                        url, param_name, 'error-based', payload, result['details'])
                    return vulnerability

                # Add delay if specified
                if self.delay > 0:
                    time.sleep(self.delay)

            except Exception as e:
                self.output.error(
                    f"Error testing payload {i+1}/{len(payloads)}: {str(e)}")
                continue

        return None

    def _test_boolean_based(self, url, param_name, params, method, baseline_response):
        """
        Test for boolean-based SQL injection

        Args:
            url (str): Target URL
            param_name (str): Parameter name to test
            params (dict): All parameters
            method (str): HTTP method
            baseline_response (requests.Response): Baseline response

        Returns:
            dict or None: Vulnerability details if found, None otherwise
        """
        self.output.info(
            f"Testing parameter '{param_name}' for boolean-based MySQL injection")

        # Use MySQL-specific boolean payloads
        payloads = self.mysql_boolean_payloads

        # For verbose output, show number of payloads
        if self.verbose:
            self.output.info(
                f"Testing with {len(payloads)} MySQL boolean-based payloads")

        # Store baseline response length for comparison
        baseline_length = len(baseline_response.text)

        # Test pairs of boolean payloads (true and false conditions)
        for i in range(0, len(payloads), 2):# duyệt payload mỗi lần lấy 2 phần tử để lấy true false
            if i + 1 >= len(payloads):
                break

            true_payload = payloads[i]     # e.g., "' AND 1=1 -- -"
            false_payload = payloads[i+1]  # e.g., "' AND 1=0 -- -"

            try:
                # Test TRUE condition
                modified_params = self._clone_and_modify_params(
                    params, param_name, true_payload)

                if method == "GET":
                    # Rebuild query string
                    query_string = '&'.join(
                        [f"{k}={v}" for k, v in modified_params.items()])
                    parsed_url = urllib.parse.urlparse(url)
                    # Replace query string
                    true_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        query_string,
                        parsed_url.fragment
                    ))

                    true_response = self.request_handler.send_request(
                        true_url, method)
                else:
                    # Rebuild POST data
                    modified_data = '&'.join(
                        [f"{k}={v}" for k, v in modified_params.items()])
                    true_response = self.request_handler.send_request(
                        url, method, modified_data)

                if not true_response:
                    continue

                # Test FALSE condition
                modified_params = self._clone_and_modify_params(
                    params, param_name, false_payload)

                if method == "GET":
                    # Rebuild query string
                    query_string = '&'.join(
                        [f"{k}={v}" for k, v in modified_params.items()])
                    parsed_url = urllib.parse.urlparse(url)
                    # Replace query string
                    false_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        query_string,
                        parsed_url.fragment
                    ))

                    false_response = self.request_handler.send_request(
                        false_url, method)
                else:
                    # Rebuild POST data
                    modified_data = '&'.join(
                        [f"{k}={v}" for k, v in modified_params.items()])
                    false_response = self.request_handler.send_request(
                        url, method, modified_data)

                if not false_response:
                    continue

                # Compare responses for boolean-based detection
                true_length = len(true_response.text)
                false_length = len(false_response.text)

                # Calculate length differences
                true_diff = abs(true_length - baseline_length)
                false_diff = abs(false_length - baseline_length)
                true_false_diff = abs(true_length - false_length)

                # Significant differences between TRUE and FALSE responses indicate boolean-based injection
                if true_false_diff > 10 and (true_diff / baseline_length > 0.1 or false_diff / baseline_length > 0.1):
                    self.output.success(
                        f"Found boolean-based MySQL injection in parameter: {param_name}")
                    self.output.success(f"TRUE payload: {true_payload}")
                    self.output.success(f"FALSE payload: {false_payload}")
                    self.output.success(
                        f"Response length differences: Baseline={baseline_length}, TRUE={true_length}, FALSE={false_length}")

                    details = (f"Boolean-based MySQL injection detected. Response length differences: "
                               f"Baseline={baseline_length}, TRUE={true_length}, FALSE={false_length}")

                    vulnerability = {
                        'type': 'boolean-based',
                        'parameter': param_name,
                        'payload': f"TRUE: {true_payload}, FALSE: {false_payload}",
                        'details': details
                    }

                    self._add_vulnerability(url, param_name, 'boolean-based',
                                            f"TRUE: {true_payload}, FALSE: {false_payload}",
                                            details)
                    return vulnerability

                # Add delay if specified
                if self.delay > 0:
                    time.sleep(self.delay)

            except Exception as e:
                self.output.error(
                    f"Error testing payload pair {i//2+1}/{len(payloads)//2}: {str(e)}")
                continue

        return None

    def _test_time_based(self, url, param_name, params, method, baseline_response):
        """
        Test for time-based SQL injection

        Args:
            url (str): Target URL
            param_name (str): Parameter name to test
            params (dict): All parameters
            method (str): HTTP method
            baseline_response (requests.Response): Baseline response

        Returns:
            dict or None: Vulnerability details if found, None otherwise
        """
        self.output.info(
            f"Testing parameter '{param_name}' for time-based MySQL injection")

        # Use MySQL-specific time payloads
        payloads = self.mysql_time_payloads

        # For verbose output, show number of payloads
        if self.verbose:
            self.output.info(
                f"Testing with {len(payloads)} MySQL time-based payloads")

        # Store baseline response time for comparison
        baseline_time = baseline_response.elapsed.total_seconds()

        for i, payload in enumerate(payloads):
            # Clone parameters and modify the tested one
            modified_params = self._clone_and_modify_params(
                params, param_name, payload)

            try:
                # Send request with modified parameters
                if method == "GET":
                    # Rebuild query string
                    query_string = '&'.join(
                        [f"{k}={v}" for k, v in modified_params.items()])
                    parsed_url = urllib.parse.urlparse(url)
                    # Replace query string
                    modified_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        query_string,
                        parsed_url.fragment
                    ))

                    start_time = time.time() # lưu thời điểm bắt đầu
                    response = self.request_handler.send_request(
                        modified_url, method)
                    elapsed_time = response.elapsed.total_seconds( # đo nếu request thành công
                    ) if response else time.time() - start_time # đo nếu thất bại
                else:
                    # Rebuild POST data
                    modified_data = '&'.join(
                        [f"{k}={v}" for k, v in modified_params.items()])

                    start_time = time.time()
                    response = self.request_handler.send_request(
                        url, method, modified_data)
                    elapsed_time = response.elapsed.total_seconds(
                    ) if response else time.time() - start_time

                if not response:
                    continue

                
                expected_sleep = 3  # Default expected sleep time
                sleep_match = re.search( #  Sử dụng re.search() để tìm chuỗi có dạng SLEEP(n) trong payload, rồi trả về n
                    r'SLEEP\((\d+)\)', payload, re.IGNORECASE) # 
                if sleep_match:
                    expected_sleep = int(sleep_match.group(1)) #  .group(1) → Lấy nội dung của nhóm đầu tiên (\d+).

                # Check for time difference indicating successful time-based injection
                if self.response_analyzer._check_time_based(baseline_time, elapsed_time, expected_sleep):
                    self.output.success(
                        f"Found time-based MySQL injection in parameter: {param_name}")
                    self.output.success(f"Payload: {payload}")
                    self.output.success(
                        f"Response times: Baseline={baseline_time:.2f}s, With payload={elapsed_time:.2f}s")

                    details = (f"Time-based MySQL injection detected. Response times: "
                               f"Baseline={baseline_time:.2f}s, With payload={elapsed_time:.2f}s")

                    vulnerability = {
                        'type': 'time-based',
                        'parameter': param_name,
                        'payload': payload,
                        'details': details
                    }

                    self._add_vulnerability(
                        url, param_name, 'time-based', payload, details)
                    return vulnerability

                # Add delay if specified (longer delay for time-based testing to avoid false positives)
                if self.delay > 0:
                    time.sleep(self.delay * 2)

            except Exception as e:
                self.output.error(
                    f"Error testing payload {i+1}/{len(payloads)}: {str(e)}")
                continue

        return None

    def _test_union_based(self, url, param_name, params, method, baseline_response):
        """
        Test for union-based SQL injection

        Args:
            url (str): Target URL
            param_name (str): Parameter name to test
            params (dict): All parameters
            method (str): HTTP method
            baseline_response (requests.Response): Baseline response

        Returns:
            dict or None: Vulnerability details if found, None otherwise
        """
        self.output.info(
            f"Testing parameter '{param_name}' for union-based MySQL injection")

        # Use MySQL-specific union payloads
        payloads = self.mysql_union_payloads

        # For verbose output, show number of payloads
        if self.verbose:
            self.output.info(
                f"Testing with {len(payloads)} MySQL union-based payloads")

        for i, payload in enumerate(payloads):
            # Clone parameters and modify the tested one
            modified_params = self._clone_and_modify_params(
                params, param_name, payload)

            try:
                # Send request with modified parameters
                if method == "GET":
                    # Rebuild query string
                    query_string = '&'.join(
                        [f"{k}={v}" for k, v in modified_params.items()])
                    parsed_url = urllib.parse.urlparse(url)
                    # Replace query string
                    modified_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        query_string,
                        parsed_url.fragment
                    ))

                    response = self.request_handler.send_request(
                        modified_url, method)
                else:
                    # Rebuild POST data
                    modified_data = '&'.join(
                        [f"{k}={v}" for k, v in modified_params.items()])
                    response = self.request_handler.send_request(
                        url, method, modified_data)

                if not response:
                    continue

                # Analyze response for UNION injection
                is_vulnerable, extracted_data = self.response_analyzer._check_union_select(
                    response.text, payload)

                if is_vulnerable:
                    self.output.success(
                        f"Found union-based MySQL injection in parameter: {param_name}")
                    self.output.success(f"Payload: {payload}")

                    details = "Union-based MySQL injection detected."
                    if extracted_data:
                        details += f" Extracted data: {extracted_data}"
                        self.output.success(
                            f"Extracted data: {extracted_data}")

                    vulnerability = {
                        'type': 'union-based',
                        'parameter': param_name,
                        'payload': payload,
                        'details': details
                    }

                    if extracted_data:
                        vulnerability['extracted_data'] = extracted_data

                    self._add_vulnerability(
                        url, param_name, 'union-based', payload, details)
                    return vulnerability

                # Add delay if specified
                if self.delay > 0:
                    time.sleep(self.delay)

            except Exception as e:
                self.output.error(
                    f"Error testing payload {i+1}/{len(payloads)}: {str(e)}")
                continue

        return None

    def _clone_and_modify_params(self, params, param_name, new_value):
        """
        Clone parameters and modify the specified one with a new value

        Args:
            params (dict): Original parameters
            param_name (str): Parameter name to modify
            new_value (str): New value for the parameter

        Returns:
            dict: Modified parameters
        """
        modified_params = {}

        for name, value in params.items():
            if name == param_name:
                # Modify the target parameter
                modified_params[name] = new_value
            else:
                # Keep original value
                modified_params[name] = value[0] if isinstance(
                    value, list) else value

        return modified_params

    def _add_vulnerability(self, url, parameter, vulnerability_type, payload, details):
        """
        Add vulnerability to results

        Args:
            url (str): Target URL
            parameter (str): Vulnerable parameter
            vulnerability_type (str): Type of vulnerability
            payload (str): Payload that triggered the vulnerability
            details (str): Additional details
        """
        vulnerability = {
            'url': url,
            'parameter': parameter,
            'type': vulnerability_type,
            'payload': payload,
            'details': details,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        self.results['vulnerabilities'].append(vulnerability)

        # Update target info
        for target in self.results['targets']:
            if target['url'] == url:
                target['vulnerabilities_found'] += 1

        # Log to console
        self.output.success(
            f"Found {vulnerability_type} SQL injection in {url} (parameter: {parameter})")
        self.output.success(f"Payload: {payload}")
        self.output.success(f"Details: {details}")

    def get_results(self):
        """Get scan results"""
        return self.results

    def get_vulnerabilities(self):
        """Get list of vulnerabilities found"""
        return self.results['vulnerabilities']
