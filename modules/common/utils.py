#!/usr/bin/env python3
"""
Common utility functions for the Web Security Fuzzer
"""

import sys
import datetime
import re
import time
import os
import json
from urllib.parse import urlparse

# ANSI color codes for console output


class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class Output:
    def __init__(self, no_color=False):
        self.no_color = no_color

    def print_info(self, message):
        """Print informational message"""
        if self.no_color:
            print(f"[*] {message}")
        else:
            print(f"{Colors.BLUE}[*]{Colors.RESET} {message}")

    # Alias for compatibility
    def info(self, message):
        return self.print_info(message)

    def print_success(self, message):
        """Print success message"""
        if self.no_color:
            print(f"[+] {message}")
        else:
            print(f"{Colors.GREEN}[+]{Colors.RESET} {message}")

    # Alias for compatibility
    def success(self, message):
        return self.print_success(message)

    def print_error(self, message):
        """Print error message"""
        if self.no_color:
            print(f"[!] {message}")
        else:
            print(f"{Colors.RED}[!]{Colors.RESET} {message}")

    # Alias for compatibility
    def error(self, message):
        return self.print_error(message)

    def print_warning(self, message):
        """Print warning message"""
        if self.no_color:
            print(f"[-] {message}")
        else:
            print(f"{Colors.YELLOW}[-]{Colors.RESET} {message}")

    # Alias for compatibility
    def warning(self, message):
        return self.print_warning(message)

    def print_detail(self, title, value):
        """Print detailed information"""
        if self.no_color:
            print(f"    {title}: {value}")
        else:
            print(f"    {Colors.CYAN}{title}{Colors.RESET}: {value}")

    # Alias for compatibility
    def detail(self, title, value):
        return self.print_detail(title, value)

    def banner(self, tool_name, version="1.0.0"):
        """Display tool banner"""
        banner_text = f"""
 __          __  _        _____            ______               
 \ \        / / | |      / ____|          |  ____|              
  \ \  /\  / /__| |__   | (___   ___  ___| |__ _   _ _________ 
   \ \/  \/ / _ \ '_ \   \___ \ / _ \/ __|  __| | | |_  /_  / _ \\ 
    \  /\  /  __/ |_) |  ____) |  __/ (__| |  | |_| |/ / / / (_) |
     \/  \/ \___|_.__/  |_____/ \___|\___|_|   \__,_/___/___\___/ 
                                                            
            Web Security Fuzzing Tool - {tool_name}
        """

        if not self.no_color:
            print(f"{Colors.CYAN}{banner_text}{Colors.RESET}")
        else:
            print(banner_text)

        print(f"Version: {version}")
        print(
            f"Started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


def parse_headers(headers_str):
    """Parse custom headers from command line"""
    headers = {}
    if headers_str:
        for header in headers_str.split(','):
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    return headers


def save_report(output_file, report_data):
    """Save report to a file"""
    if not output_file:
        return False

    try:
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=4)
        return True
    except Exception as e:
        print(f"[!] Error saving report: {e}")
        return False


def is_valid_url(url):
    """Check if URL is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def is_same_domain(url1, url2):
    """Check if two URLs are from the same domain"""
    try:
        domain1 = urlparse(url1).netloc
        domain2 = urlparse(url2).netloc
        return domain1 == domain2
    except Exception:
        return False


def get_filename_from_url(url):
    """Get filename from URL"""
    try:
        path = urlparse(url).path
        return os.path.basename(path)
    except Exception:
        return ""
