import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

base_url = "http://fao.org"
endpoints = [
    "/",
    "/login",
    "/search",
    "/profile",
    "/admin"
]

# Payloads for testing
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
]

csrf_payloads = [
    {"key": "csrf_token", "value": "dummy_token"}
]

sql_injection_payloads = [
    "' OR '1'='1",  # SELECT * FROM users WHERE username = 'input' AND password = 'input';
    "' AND 1=1 --", # SELECT * FROM users WHERE username = 'input' AND password = 'input';
]


security_headers = [
    "Strict-Transport-Security",  # HSTS for HTTPS

    "X-Content-Type-Options",     # Prevent MIME-sniffing
    "X-Frame-Options",            # Clickjacking protection
    "Content-Security-Policy",    # Protect from XSS
    "Referrer-Policy"             # Reduce referrer leakage
]

def test_xss(url):
    for payload in xss_payloads:
        response = requests.get(url, params={'test': payload})
        # Detect if payload is reflected in the response
        if payload in response.text:
            print(f"[XSS] Potential XSS vulnerability detected at {url} with payload: {payload}")

def test_csrf(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'lxml')
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        if not action:
            action = url
        form_url = urljoin(url, action)
        form_data = {input.get('name', ''): 'test' for input in form.find_all('input')}
        # Add CSRF token to form data
        for token in csrf_payloads:
            form_data[token["key"]] = token["value"]
        response = requests.post(form_url, data=form_data)
        if response.status_code == 403:
            print(f"[CSRF] Potential CSRF vulnerability detected at {url} with form data: {form_data}")

def test_sql_injection(url):
    for payload in sql_injection_payloads:
        response = requests.get(url, params={'search': payload})
        # Checking if there's an error response 
        if "error" in response.text.lower():
            print(f"[SQL Injection] Potential SQL Injection vulnerability detected at {url} with payload: {payload}")


def test_security_headers(url):
    response = requests.get(url)
    missing_headers = []
    for header in security_headers:
        if header not in response.headers:
            missing_headers.append(header)
    
    if missing_headers:
        print(f"[Security Headers] Missing security headers at {url}: {', '.join(missing_headers)}")
    else:
        print(f"[Security Headers] All necessary security headers are present at {url}")

def test_ssl_cert(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme == 'https':
        try:
            response = requests.get(url, verify=True)
            print(f"[SSL] SSL certificate valid for {url}")
        except requests.exceptions.SSLError:
            print(f"[SSL] Invalid SSL certificate detected at {url}")
    else:
        print(f"[SSL] {url} does not use HTTPS. Consider using HTTPS for secure communication.")

def test_insecure_endpoints(url):
    response = requests.get(url)
    # Detect potential issues with the endpoint response
    if response.status_code == 200 and len(response.text) < 1000:
        print(f"[Insecure Endpoint] Insecure endpoint detected at {url}: Low response content length")
    elif response.status_code == 403:
        print(f"[Insecure Endpoint] Insecure endpoint detected at {url}: Access Forbidden")
    elif response.status_code == 404:
        print(f"[Insecure Endpoint] Insecure endpoint detected at {url}: Not Found")

def test_open_redirects(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'lxml')
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        if action:
            # Check if the form action leads to an external domain (potential open redirect)
            form_url = urljoin(url, action)
            parsed_form_url = urlparse(form_url)
            parsed_base_url = urlparse(url)
            if parsed_form_url.netloc and parsed_form_url.netloc != parsed_base_url.netloc:
                print(f"[Open Redirect] Potential open redirect at {url}: {form_url}")


def scan_web_app():
    for endpoint in endpoints:
        url = urljoin(base_url, endpoint)
        print(f"\nScanning {url}...")
        test_xss(url)
        test_csrf(url)
        test_sql_injection(url)
        test_insecure_endpoints(url)
        test_security_headers(url)
        test_ssl_cert(url)
        test_open_redirects(url)

if __name__ == "__main__":
    scan_web_app()
