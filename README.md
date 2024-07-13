<p align="center"><a href="https://github.com/TalMaIka/Site-Scanner"><img src="src/barcode.png" alt="Site-Scanner icon" height="60"/></a></p>
<h1 align="center">Site-Scanner</h1>
<p align="center">Web Application Vulnerability Assessment Tool.</p>


<p align="center"><a href="https://github.com/TalMaIka/Site-Scanner"><img src="src/Ver-1.8.0.png" alt="Site-Scanner icon" height="550"/></a></p>


## :dart: Features

- **Basic Info:** Quick site information (Load Time, IP Address, Server OS...).
- **Robots.txt Disallow Entries:** Detection of Robots.txt and printing Disallow Entries.
- **CMS Detection & Vulnerability Report:** Automatically identifies the CMS and generates a vulnerability report.
- **Admin Panel Auth Detection:** Searches for common login page variations based on the detected CMS.
- **Directory Scanning:** Searches for valid directories under the specified URL.
- **Security Headers Check:** Checks for the presence of important security headers.
- **SSL Certificate Validation:** Validates the SSL/TLS certificate for the domain, displaying issuer information, expiration date, and days until expiry.
- **Open Ports Scan:** Scans open ports on the server.
- **Subdomain Scanning:** Scans for subdomains of the specified URL.
- **SQL Injection Detection:** Tests for SQL injection vulnerabilities in query parameters.
- **XSS Detection:** Tests for cross-site scripting vulnerabilities.
- **User-Friendly Interface:** Interactive and detailed shell menu.
- **Multi-Threaded:** Efficiently performs tasks in the background using threading.


## :zap: Getting Started

### Prerequisites

- Python 3.x.x
- Required Python packages: `requests`, `beautifulsoup4`

### Installation

1. Clone the repository: `git clone https://github.com/TalMaIka/Site-Scanner.git`
2. Navigate to the project directory: `cd Site-Scanner`
3. Requirements Installation: `pip install -r requirements.txt`

## :rocket: Usage

1. Run the tool: `python3 Site-Scanner.py` / Proxychains `proxychains python3 Site-Scanner.py`
2. Enter the URL of the website you wish to analyze.
3. Choose tasks according to the menu.

## :copyright: Contributing

Found a bug or want to contribute? Great! Please submit an issue or pull request.
