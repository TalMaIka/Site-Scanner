# ![icon](src/icons8-security-scan-45.png)Site Scanner

Site-Scanner makes it easy to perform security checks to ensure websites safety. 

![Project Screenshot](Runtime.gif)

## Features

- **Ver 1.3:** Few CMS variations added, Robots.txt Lookup and automatic results saving.

- **Basic Info:** Quick site information (Load Time, IP Address, Server OS...).
- **Robots.txt Lookup:** Looking for the Robots.txt in the default location and analysing it.
- **CMS Detection:** Automatically identifies the CMS used by a website (WordPress, Joomla, Drupal, etc.).
- **Login Page Search:** Searches for common login page variations based on the detected CMS.
- **SQL Injection Check:** Tests for SQL injection vulnerabilities in query parameters.
- **XSS Detection:** Tests for SQL injection vulnerabilities in query parameters.
- **User-Friendly Interface:** Interactive and detailed shell menu.
- **Multi-Threaded:** Efficiently performs tasks in the background using threading.


## Getting Started

### Prerequisites

- Python 3.x
- Required Python packages: `requests`, `beautifulsoup4`

### Installation

1. Clone the repository: `git clone https://github.com/TalMaIka/Site-Scanner.git`
2. Navigate to the project directory: `cd Site-Scanner`

## Usage

1. Run the tool: `python3 Site-Scanner.py`
2. Enter the URL of the website you want to analyze.
4. Choose your tasks according to the menu.

## Contributing

Found a bug or want to contribute? Great! Please submit an issue or pull request.
