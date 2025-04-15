#!/usr/bin/env python3
"""
Response Analyzer module for the SQL Injection Scanner
"""

import re
from modules.sql.mysql_payloads import get_mysql_error_patterns


class ResponseAnalyzer:
    def __init__(self, verbose=False):
        self.verbose = verbose

        # Initialize patterns for SQL error detection
        self._init_patterns()

    def _init_patterns(self):
        """Initialize regex patterns for SQL error detection with focus on MySQL"""

        # MySQL error patterns from specialized module
        self.mysql_error_patterns = get_mysql_error_patterns()

        # Là danh sách các biểu thức chính quy (regex) để phát hiện lỗi SQL chung.
        self.generic_error_patterns = [
            r"DB Error",
            r"SQL Error",
            r"SQL syntax.*",
            r"Warning.*SQL.*",
            r"Warning.*syntax.*",
            r"Warning.*for user '.*'",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Microsoft OLE DB Provider for SQL Server error",
            r"ODBC.*Driver",
            r"Error.*\bODBC\b.*Driver",
            r"Exception.*java\.sql\.SQLException",
            r"Unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
            r"Syntax error.*in query expression",
            r"Data type mismatch"
        ]

        # mẫu lỗi dành cho union
        self.union_select_patterns = [
            r"\b\d+\b\s*,\s*\b\d+\b",           # For simple numeric columns like "1, 2, 3"
            r"[0-9]+ rows in set",              # MySQL rows message
            r"appears more than once in the SELECT list",
            # MySQL UNION detection patterns
            # Common MySQL functions exposed via UNION
            r"(version\(\)|user\(\)|database\(\))",
            r"for a right syntax to use near 'UNION SELECT",  # UNION error
            r"The used SELECT statements have a different number of columns",  # Column count error
            # HTML table output with numbers
            r"<td>\s*\d+\s*</td>\s*<td>\s*[^<]+\s*</td>",
            r"UNION ALL SELECT",
            r"UNION SELECT"
        ]

        # 1 số mẫu lỗi cho MySQL Boolean-Based và Error-Based SQL Injection.
        self.data_extraction_patterns = [
            r"XPATH syntax error: '([^']*)'",  # UPDATEXML/EXTRACTVALUE data
            r"EXTRACTVALUE\(.*,.*'~([^~]*)~'",
            r"UPDATEXML\(.*,.*'~([^~]*)~'",
            r"Duplicate entry '([^']*)' for key",  # GROUP BY data extraction
            r"(?<=\~).*(?=\~)"  # Extract data between tildes
        ]

        # kiểm tra bypass thành công k thôi
        self.auth_bypass_patterns = [
            r"Welcome.*admin",
            r"Login successful",
            r"Admin.*panel",
            r"Dashboard",
            r"Logout",
            r"administrator",
            r"successfully logged in",
            r"authentication successful"
        ]

    def analyze(self, response, payload):
        """
        Analyze response to detect potential SQL injection vulnerabilities

        Args:
            response (requests.Response): HTTP response object
            payload (str): The SQL injection payload that was used

        Returns:
            dict: Analysis result containing vulnerability status and details
        """
        result = {
            'vulnerable': False,
            'details': '',
            'type': None,
            'extracted_data': None
        }

        # Check if response is valid
        if not response or not hasattr(response, 'text'): #  là hàm built-in trong Python, dùng để kiểm tra xem một object có thuộc tính cụ thể hay không.
            return result

        # Store original response info
        status_code = response.status_code
        response_text = response.text
        content_length = len(response_text)

        # Check for SQL errors in response
        is_error, error_data = self._check_sql_errors(response_text)
        if is_error:
            result['vulnerable'] = True
            result['type'] = 'error-based'
            result['details'] = f"SQL error detected in response"
            result['extracted_data'] = error_data
            return result

        # Check for UNION SELECT patterns
        is_union, union_data = self._check_union_select(response_text, payload)
        if is_union:
            result['vulnerable'] = True
            result['type'] = 'union-based'
            result['details'] = f"UNION-based SQL injection detected"
            result['extracted_data'] = union_data
            return result

        # Check for authentication bypass
        if self._check_auth_bypass(response_text):
            result['vulnerable'] = True
            result['type'] = 'auth-bypass'
            result['details'] = f"Potential authentication bypass detected"
            return result

        return result

    def _check_sql_errors(self, response_text):
        """
        Check for SQL errors in the response text

        Args:
            response_text (str): HTTP response text

        Returns:
            tuple: (is_vulnerable, extracted_data)
        """
        # First check for MySQL specific errors
        for pattern in self.mysql_error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE) # lấy mẫu pattern ở file payload xong tìm kiếm 1 mẫu khớp ở trong response
            if match:
                # Try to extract any data from the error message
                extracted_data = self._extract_data_from_error(response_text)
                if self.verbose:
                    print(f"[+] MySQL error detected: {match.group(0)}") # group(0) trả về toàn bộ chuối khớp đầu tiên từ đoạn khớp
                return True, extracted_data

        # Then check for generic SQL errors
        for pattern in self.generic_error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                if self.verbose:
                    print(f"[+] Generic SQL error detected: {match.group(0)}")
                return True, None

        return False, None

    def _extract_data_from_error(self, response_text):# trên kia kiểm tra xem có lỗi trả về giống mẫu được lưu k, còn hàm này kiểm tra kĩ xem lỗi trả về có chứa thông tin nhạy cảm k
        """Extract data from SQL error messages"""
        extracted_data = []

        for pattern in self.data_extraction_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE) # tìm tất cả các mẫu khớp
            if matches:
                extracted_data.extend(matches) # Thêm từng phần tử trong matches vào extracted_data khác với append

        return extracted_data if extracted_data else None

    def _check_union_select(self, response_text, payload):
        """
        Check for successful UNION-based SQL injection

        Args:
            response_text (str): HTTP response text
            payload (str): The SQL payload that was used

        Returns:
            tuple: (is_vulnerable, extracted_data)
        """
        # First check if payload contains UNION
        if not re.search(r"union\s+(?:all\s+)?select", payload, re.IGNORECASE):# tìm mấy chuỗi truy vấn có dạng này: union select password FROM admin
            return False, None # đảm bảo payload có dạng union để kiểm tra thôi

        # Look for patterns indicating successful UNION injection
        for pattern in self.union_select_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                if self.verbose:
                    print(
                        f"[+] UNION SELECT pattern detected: {match.group(0)}")

                # Try to extract data from response
                data = self._extract_data_from_union(response_text, payload)
                return True, data

        return False, None

    def _extract_data_from_union(self, response_text, payload):# cái này vẫn để đi sâu vào response xem có phản hồi 1 số thông tin nhạy cảm hơn k thôi
        """Extract data from UNION-based injection responses"""
        # Extract data based on payload type
        data = []

        # Look for numeric markers in tables (1,2,3,etc.)
        numeric_markers = re.findall(r"<td>\s*(\d+)\s*</td>", response_text) # tìm các sô nguyên giữa các thẻ  <tr><td>456</td></tr> để tìm số cột thôi
        if numeric_markers:
            data.append(f"Found numeric markers: {', '.join(numeric_markers)}")

        # Look for MySQL version, user, database info
        version_match = re.search(
            r"<td>[^<]*?(\d+\.\d+\.\d+)[^<]*?</td>", response_text)
        if version_match:
            data.append(f"Possible MySQL version: {version_match.group(1)}")

        user_match = re.search(
            r"<td>[^<]*?(root@|[^<@]+@[^<]+)[^<]*?</td>", response_text)
        if user_match:
            data.append(f"Possible database user: {user_match.group(1)}")

        return data if data else None

    def _check_auth_bypass(self, response_text):# cái này chưa dùng
        """Check for signs of successful authentication bypass"""
        for pattern in self.auth_bypass_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                if self.verbose:
                    print(f"[+] Authentication bypass pattern detected")
                return True
        return False

    def compare_responses(self, baseline_response, test_response):# hàm này k dùng đến vì bên scan sql nó so sánh rồi
        """
        Compare two responses to detect blind SQL injection

        Args:
            baseline_response (requests.Response): Original response
            test_response (requests.Response): Response with injected payload

        Returns:
            bool: True if significant difference detected, False otherwise
        """
        if not baseline_response or not test_response:
            return False

        # Check for significant status code differences
        if baseline_response.status_code != test_response.status_code:
            if self.verbose:
                print(
                    f"[+] Status code difference: {baseline_response.status_code} vs {test_response.status_code}")
            return True

        # Compare response lengths (for boolean-based detection)
        baseline_length = len(baseline_response.text)
        test_length = len(test_response.text)

        # If length difference is significant (>10%)
        length_diff = abs(baseline_length - test_length)
        if length_diff > 0 and (length_diff / baseline_length) > 0.10:
            if self.verbose:
                print(
                    f"[+] Response length difference: {baseline_length} vs {test_length}")
            return True

        return False

    def _check_time_based(self, baseline_time, response_time, sleep_time=3):
        """
        Check for time-based SQL injection by comparing response times

        Args:
            baseline_time (float): Original response time
            response_time (float): Response time with injected payload
            sleep_time (int): Expected sleep time in payload

        Returns:
            bool: True if significant time difference detected, False otherwise
        """
        # If response time is at least 80% of the sleep time and significantly
        # longer than baseline, likely time-based injection
        if response_time > (sleep_time * 2) and response_time > (baseline_time * 2):
            if self.verbose:
                print(
                    f"[+] Time-based difference detected: {baseline_time:.2f}s vs {response_time:.2f}s")
            return True
        return False
