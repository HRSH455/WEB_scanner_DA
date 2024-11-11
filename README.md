
---

# Web Application Security Scanner

### A Python-based tool to assess security vulnerabilities in web applications

## Overview

The Web Application Security Scanner helps developers and security professionals detect common vulnerabilities in web applications, including:
- **Cross-Site Scripting (XSS)**
- **SQL Injection**
- **Cross-Site Request Forgery (CSRF)**
- **Directory Traversal**
- **Insecure Endpoint Configurations**

By scanning specified web application endpoints, this tool provides a quick, proactive approach to identifying and addressing security risks before they can be exploited in a production environment.

## Features

- **Modular Scanning** for various vulnerabilities
- **Risk Scoring** to prioritize identified issues
- **JSON Reporting** for detailed analysis and documentation
- **Logging** of findings and errors for troubleshooting
- **Configurable Payloads and Endpoints** to customize scan settings

## Requirements

- **Python 3.x**
- **Internet Connection** for scanning live endpoints
- Python Libraries:
  - `requests`
  - `beautifulsoup4`
  - `logging`

Install the required libraries by running:
```bash
pip install requests beautifulsoup4
```

## Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/web-app-security-scanner.git
   cd web-app-security-scanner
   ```

2. **(Optional) Create a Virtual Environment**:
   ```bash
   python -m venv scanner_env
   source scanner_env/bin/activate  # On Windows, use scanner_env\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Configure `base_url` and `endpoints`**:
   - Open `cybers_da2.py` in a code editor.
   - Define the `base_url` variable with the URL of the target web application.
   - Populate the `endpoints` list with the paths to be scanned.

2. **Run the Scanner**:
   ```bash
   python cybers_da2.py
   ```

3. **Review Results**:
   - **Console Output**: Provides a summary of detected vulnerabilities.
   - **Log File** (`security_scan.log`): Contains detailed logs of the scan process.
   - **JSON Report** (`security_scan_report.json`): Comprehensive report with vulnerability details and risk scores.

## Example

After setting `base_url` to `https://victoryschools.in` and specifying relevant endpoints, running the scanner may produce console output like this:

```
Scan Summary:
--------------------------------------------------
Total endpoints scanned: 11
Total vulnerabilities found: 15

Vulnerabilities for https://victoryschools.in/:
- Insecure Configuration: Vulnerable to clickjacking
- Insecure Configuration: MIME-sniffing vulnerability
- Insecure Configuration: No Content Security Policy

Vulnerabilities for https://victoryschools.in/Victory/Faculty/faculty_login.php:
- CSRF: No CSRF token found in form
- Insecure Configuration: Vulnerable to clickjacking
- Insecure Configuration: MIME-sniffing vulnerability
- Insecure Configuration: No Content Security Policy

Vulnerabilities for https://victoryschools.in/Victory/Admin/admin_login.php:
- CSRF: No CSRF token found in form
- Insecure Configuration: Vulnerable to clickjacking
- Insecure Configuration: MIME-sniffing vulnerability
- Insecure Configuration: No Content Security Policy

Vulnerabilities for https://victoryschools.in/Victory/Student/student_login.php:
- CSRF: No CSRF token found in form
- Insecure Configuration: Vulnerable to clickjacking
- Insecure Configuration: MIME-sniffing vulnerability
- Insecure Configuration: No Content Security Policy
```

## Modules

- **WebSecurityScanner Class**: Manages scanning and vulnerability detection across endpoints.
- **Vulnerability Tests**:
  - `test_xss()`: Scans for XSS vulnerabilities.
  - `test_csrf()`: Checks for missing CSRF tokens.
  - `test_sql_injection()`: Tests for SQL injection vulnerabilities.
  - `test_directory_traversal()`: Detects directory traversal vulnerabilities.
  - `test_insecure_endpoints()`: Identifies insecure configurations in endpoints.
- **Helper Functions**:
  - `make_request()`: Handles HTTP requests and error logging.
  - `calculate_risk_metrics()`: Analyzes vulnerabilities and calculates risk scores.
  - `generate_report()`: Generates a JSON report summarizing scan results.

## Customization

- **Add New Payloads**: To test additional vulnerability patterns, modify payload lists (e.g., `xss_payloads`, `sql_injection_payloads`) within the script.
- **Adjust Concurrency**: Modify `max_threads` in the `WebSecurityScanner` class to control the number of concurrent requests.

## Future Enhancements

- Support for authenticated scanning to access restricted endpoints
- PDF/CSV report generation
- Improved error handling and exception reporting

## Contributing

Contributions are welcome! Please open an issue to discuss any changes or submit a pull request.

---
