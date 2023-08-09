# Site Checker - A tool to gather information about a website.
# Author: Tal.M
# Date: August 5, 2023
# Copyright © 2023 Tal.M. All rights reserved.

import requests
from bs4 import BeautifulSoup
import time
import requests
from urllib.parse import urlparse
import socket
import concurrent.futures


def get_url():
    global url
    while True:
        url = input('Enter URL: ')
        if not url:
            print('Invalid URL')
        elif not url.startswith('http'):
            print('\033[31mInvalid URL\033[0m, Example: http://example.com')
        elif url.endswith('/'):
            url = url[:-1]
            return url
        else:
            return url


def detect_cms(html):
    print("\033[32mDetecting CMS\033[0m")
    soup = BeautifulSoup(html, 'html.parser')

    # Detect WordPress
    if "wordpress" in html.lower():
        return "\033[31m - \033[0m" + "WordPress"

    # Detect Joomla
    if soup.find("meta", {"name": "generator", "content": "Joomla! - Open Source Content Management"}):
        return "\033[31m - \033[0m" + "Joomla"

    # Detect Drupal
    if soup.find("meta", {"name": "Generator", "content": "Drupal"}):
        return "\033[31m - \033[0m" + "Drupal"

    # Detect Wix
    if "wix.com" in html:
        return "\033[31m - \033[0m" + "Wix"

    # Detect Squarespace
    if "squarespace.com" in html:
        return "\033[31m - \033[0m" + "Squarespace"

    # Detect vBulletin
    if "vbulletin" in html:
        return "\033[31m - \033[0m" + "vBulletin"

    # Detect Magento
    if soup.find("meta", {"name": "generator", "content": "Magento"}):
        return "\033[31m - \033[0m" + "Magento"

    # Detect Shopify
    if soup.find("meta", {"name": "generator", "content": "Shopify"}):
        return "\033[31m - \033[0m" + "Shopify"

    # Detect Blogger
    if soup.find("meta", {"name": "generator", "content": "Blogger"}):
        return "\033[31m - \033[0m" + "Blogger"

    # Detect Ghost
    if soup.find("meta", {"name": "generator", "content": "Ghost"}):
        return "\033[31m - \033[0m" + "Ghost"

    return "Unknown CMS"


def search_login_variations(cms_name, url):
    print("\033[32mLogin Pages Found\033[0m")

    if "wordpress" in cms_name.lower():
        variations = [
            "/wp-login.php", "/wp-admin", "/admin", "/login",
            "/wp/wp-login.php", "/wp-admin.php"
        ]
    elif "joomla" in cms_name.lower():
        variations = [
            "/administrator", "/admin", "/backend", "/login",
            "/joomla/administrator", "/joomla/admin", "/joomla/login"
        ]
    elif "vbulletin" in cms_name.lower():
        variations = [
            "/login.php", "/login.html", "/admincp", "/admincp/login.php",
            "/admincp/login.html", "/forum/login.php", "/forum/login.html",
            "/forums/login.php", "/forums/login.html", "/vb/login.php",
            "/vb/login.html"
        ]
    elif "drupal" in cms_name.lower():
        variations = [
            "/user/login", "/user", "/user/signin", "/user/login.php",
            "/user/login.html", "/user/log-in", "/drupal/user/login"
        ]
    elif "magento" in cms_name.lower():
        variations = [
            "/admin", "/admin/login", "/admin/signin", "/admin/login.php",
            "/admin/login.html", "/admin/log-in"
        ]
    elif "shopify" in cms_name.lower():
        variations = [
            "/admin", "/admin/login", "/admin/signin", "/admin/login.php",
            "/admin/login.html", "/admin/log-in"
        ]
    elif "woocommerce" in cms_name.lower():
        variations = [
            "/wp-login.php", "/wp-admin", "/admin", "/login",
            "/wp/wp-login.php", "/wp-admin.php", "/shop/login", "/woocommerce/login"
        ]
    elif "prestashop" in cms_name.lower():
        variations = [
            "/admin", "/admin-dev", "/backend", "/signin", "/login",
            "/prestashop/admin", "/prestashop/login"
        ]
    elif "opencart" in cms_name.lower():
        variations = [
            "/admin", "/admin/index.php", "/backend", "/login",
            "/opencart/admin", "/opencart/login"
        ]
    elif "phpmyadmin" in cms_name.lower():
        variations = [
            "/phpmyadmin", "/pma", "/myadmin", "/mysql", "/db",
            "/phpMyAdmin/index.php", "/phpMyAdmin/login"
        ]
    elif "cpanel" in cms_name.lower():
        variations = [
            "/cpanel", "/controlpanel", "/cp",
            "/cpanel/index.php", "/cpanel/login"
        ]
    elif "phpbb" in cms_name.lower():
        variations = [
            "/adm", "/adm/index.php", "/admin", "/admin/index.php",
            "/login", "/phpbb/admin", "/phpbb/login"
        ]
    elif "mybb" in cms_name.lower():
        variations = [
            "/admin", "/admin/index.php", "/adm", "/adm/index.php",
            "/login", "/mybb/admin", "/mybb/login"
        ]
    elif "unknown cms" in cms_name.lower():
        variations = [
            "/adminarea",
            "/adminarea.php",
            "/adminarea.html",
            "/admin-login",
            "/wp-login.php",
            "/admin-login.php",
            "/admin-login.html",
            "/admin1",
            "/admin.php",
            "/admin",
            "/adminlogin",
            "/admin1.php",
            "/admin1.html",
            "/admin2",
            "/admin2.php",
            "/admin2.html",
            "/yonetim",
            "/yonetim.php",
            "/yonetim.html",
            "/yonetici",
            "/yonetici.php",
            "/yonetici.html",
            "/ccms",
            "/ccms.php",
            "/ccms.html",
            "/panel",
            "/panel.php",
            "/panel.html",
            "/controlpanel",
            "/controlpanel.php",
            "/controlpanel.html",
            "/admincontrol",
            "/admincontrol.php",
            "/admincontrol.html",
            "/admin1.asp",
            "/admin2.asp",
            "/yonetim.asp",
            "/yonetici.asp",
            "/ccms.asp",
            "/panel.asp",
            "/controlpanel.asp",
            "/admincontrol.asp",
            "/admin/account",
            "/admin/account.php",
            "/admin/account.html",
            "/admin/admin",
            "/admin/admin.php",
            "/admin/admin.html",
            "/admin-login.asp",
            "/admin1/login",
            "/admin2/login",
            "/yonetim/login",
            "/yonetici/login",
            "/ccms/login",
            "/panel/login",
            "/controlpanel/login",
            "/admincontrol/login",
            "/admin/account/login",
            "/admin1/login.asp",
            "/admin2/login.asp",
            "/yonetim/login.asp",
            "/yonetici/login.asp",
            "/ccms/login.asp",
            "/panel/login.asp",
            "/controlpanel/login.asp",
            "/admincontrol/login.asp",
            "/admin/account/login.asp",
            "/admin-login/login",
            "/admin/admin-login",
            "/admin-login/admin",
            "/admin-login/login.asp",
            "/admin1/login",
            "/admin2/login",
            "/yonetim/login",
            "/yonetici/login",
            "/ccms/login",
            "/panel/login",
            "/controlpanel/login",
            "/admincontrol/login",
            "/admin/account/login",
            "/login.php",
            "/login.html",
            "/signin.php",
            "/signin.html",
            "/log-in.php",
            "/log-in.html",
            "/userlogin",
            "/userlogin.php",
            "/userlogin.html",
            "/administratorlogin",
            "/administratorlogin.php",
            "/administratorlogin.html",
            "/adminlogin",
            "/adminlogin.php",
            "/adminlogin.html",
            "/secureadmin",
            "/secureadmin.php",
            "/secureadmin.html",
            "/webmaster",
            "/webmaster.php",
            "/webmaster.html",
            "/sysadmin",
            "/sysadmin.php",
            "/sysadmin.html",
            "/systemadmin",
            "/systemadmin.php",
            "/systemadmin.html",
            "/manager",
            "/manager.php",
            "/manager.html",
            "/moderator",
            "/moderator.php",
            "/moderator.html",
            "/webadmin",
            "/webadmin.php",
            "/webadmin.html",
            "/siteadmin",
            "/siteadmin.php",
            "/siteadmin.html",
            "/login-admin",
            "/login-admin.php",
            "/login-admin.html",
            "/admin1/login",
            "/admin1/login.php",
            "/admin1/login.html",
            "/admin2/login",
            "/admin2/login.php",
            "/admin2/login.html",
            "/admins.php",
            "/admins.html",
            "/admins/login.php",
            "/admins/login.html",
            "/admins/signin.php",
            "/admins/signin.html",
            "/admins/log-in.php",
            "/admins/log-in.html",
            "/administrator1.php",
            "/administrator1.html",
            "/administrator1/login.php",
            "/administrator1/login.html",
            "/administrator1/signin.php",
            "/administrator1/signin.html",
            "/administrator1/log-in.php",
            "/administrator1/log-in.html",
            "/administrator2.php",
            "/administrator2.html",
            "/administrator2/login.php",
            "/administrator2/login.html",
            "/administrator2/signin.php",
            "/administrator2/signin.html",
            "/administrator2/log-in.php",
            "/administrator2/log-in.html",
            "/login-admin1",
            "/login-admin1.php",
            "/login-admin1.html",
            "/login-admin2",
            "/login-admin2.php",
            "/login-admin2.html",
            "/admin_login.php",
            "/admin_login.html",
            "/admin_login/login.php",
            "/admin_login/login.html",
            "/admin_login/sign"
        ]
    else:
        variations = []

    valid_login_page = None
    for variation in variations:
        response = requests.get(f"{url}{variation}")
        if response.status_code == 200:
            valid_login_page = f"\033[31m - \033[0m {url}{variation}"
            break

    return valid_login_page


def get_ip(url):
    global ip_address
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except Exception as e:
        print("Error:", e)
        return "N/A"


def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    if result == 0:
        return port

def get_open_ports(ip_address):
    print("\033[32mSearching for Open Ports\033[0m")

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_port = {executor.submit(scan_port, ip_address, port): port for port in range(1, 65536)}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            if future.result() is not None:
                open_ports.append(port)

    return open_ports


def get_server_info():
    try:
        start_time = time.time()
        response = requests.get(url)
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
            print(f"\033[31mServer OS:\033[0m {os}\n")

        else:
            print('Failed to fetch URL:', response.status_code)
    except requests.exceptions.RequestException as e:
        print("Error:", e)
# def perform_task_2():
#     html = response.text
#     cms_name = detect_cms(html)
#     login_variations = search_login_variations(cms_name, url)
#     print(login_variations)

if __name__ == '__main__':
    logo = """
   _____ _ _               _____ _               _             
  / ____(_) |             / ____| |             | |            
 | (___  _| |_ ___ ______| |    | |__   ___  ___| | _____ _ __ 
  \___ \| | __/ _ \______| |    | '_ \ / _ \/ __| |/ / _ \ '__|
  ____) | | ||  __/      | |____| | | |  __/ (__|   <  __/ |   
 |_____/|_|\__\___|       \_____|_| |_|\___|\___|_|\_\___|_|   
 © Tal.M
"""
    print(logo)
    url = get_url()

    while True:
        print("\033[31m1.Basic Info\033[0m")
        print("\033[31m2.CMS & Login Page Detection\033[0m")
        print("\033[31m3.Port Scan\033[0m - Heavy Op")
        print("\033[31m4.XSS Detection\033[0m")
        print("\033[31m5.SQL Injection Detection\033[0m")
        print("\033[31m6.Exit\033[0m")
        user = input("\033[32mSelect Task:\033[0m")

        if user == '1':
            get_server_info()
        elif user == '2':
            perform_task_2()
        elif user == '3':
            ip_address = get_ip(url)
            open_ports = get_open_ports(ip_address)
            print("Open Ports:", open_ports)
        elif user == '6':
            exit()
        else:
            print("Invalid selection.")

    # get_server_info(response)
    # open_ports = get_open_ports(ip_address)
    #
    # if open_ports:
    #     print("Open Ports:", open_ports)
    # else:
    #     print("No open ports found.")
    # if response.status_code == 200:
    #     html = response.text
    #     # cms_name = detect_cms(html)
    #     # print(cms_name)
    #     # print(search_login_variations(cms_name, url))
    # else:
    #     print('Failed to fetch URL:', response.status_code)
