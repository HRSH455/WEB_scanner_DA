import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
from datetime import datetime
import logging

# Configuration
base_url = "https://www.fao.org/"
endpoints = [
    "/",
    "/login",
    "/search",
    "/profile",
    "/admin",
    "/api",
    "/upload",
    "/settings"
]

# Enhanced payloads for testing
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "<svg onload='alert(1)'>",
    "javascript:alert(1)"
]

csrf_payloads = [
    {"key": "csrf_token", "value": "dummy_token"},
    {"key": "_token", "value": "invalid_token"}
]

sql_injection_payloads = [
    "' OR '1'='1",
    "' AND 1=1 --",
    "1'; DROP TABLE users--",
    "1' UNION SELECT username,password FROM users--"
]

# New payload types
directory_traversal_payloads = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//etc/passwd"
]

# Risk levels and scores
RISK_LEVELS = {
    'XSS': 7,
    'CSRF': 6,
    'SQL_INJECTION': 9,
    'INSECURE_ENDPOINT': 4,
    'DIRECTORY_TRAVERSAL': 8
}

def setup_logging():
    """Setup basic logging configuration"""
    logging.basicConfig(
        filename='security_scan.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def make_request(url, method='GET', **kwargs):
    """Make HTTP request with error handling"""
    try:
        response = requests.request(method, url, timeout=10, **kwargs)
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed for {url}: {str(e)}")
        return None

def test_xss(url):
    vulnerabilities = []
    for payload in xss_payloads:
        response = make_request(url, params={'test': payload})
        if response and payload in response.text:
            vuln = {
                'type': 'XSS',
                'url': url,
                'payload': payload,
                'risk_score': RISK_LEVELS['XSS']
            }
            vulnerabilities.append(vuln)
            logging.warning(f"[XSS] Vulnerability found at {url}")
    return vulnerabilities

def test_csrf(url):
    vulnerabilities = []
    response = make_request(url)
    if not response:
        return vulnerabilities

    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')

    for form in forms:
        action = form.get('action', '')
        form_url = urljoin(url, action) if action else url
        form_data = {input.get('name', ''): 'test' for input in form.find_all('input')}
        
        # Check for CSRF token
        csrf_found = any('csrf' in input.get('name', '').lower() for input in form.find_all('input'))
        if not csrf_found:
            vuln = {
                'type': 'CSRF',
                'url': form_url,
                'risk_score': RISK_LEVELS['CSRF']
            }
            vulnerabilities.append(vuln)
            logging.warning(f"[CSRF] Vulnerability found at {form_url}")
    
    return vulnerabilities

def test_sql_injection(url):
    vulnerabilities = []
    for payload in sql_injection_payloads:
        response = make_request(url, params={'search': payload})
        if response and any(error in response.text.lower() for error in ['sql', 'database error', 'mysql', 'sqlite']):
            vuln = {
                'type': 'SQL_INJECTION',
                'url': url,
                'payload': payload,
                'risk_score': RISK_LEVELS['SQL_INJECTION']
            }
            vulnerabilities.append(vuln)
            logging.warning(f"[SQL Injection] Vulnerability found at {url}")
    return vulnerabilities

def test_directory_traversal(url):
    vulnerabilities = []
    for payload in directory_traversal_payloads:
        response = make_request(url, params={'path': payload})
        if response and any(pattern in response.text for pattern in ['root:', 'Windows', '[boot loader]']):
            vuln = {
                'type': 'DIRECTORY_TRAVERSAL',
                'url': url,
                'payload': payload,
                'risk_score': RISK_LEVELS['DIRECTORY_TRAVERSAL']
            }
            vulnerabilities.append(vuln)
            logging.warning(f"[Directory Traversal] Vulnerability found at {url}")
    return vulnerabilities

def test_insecure_endpoints(url):
    vulnerabilities = []
    response = make_request(url)
    if not response:
        return vulnerabilities

    if response.status_code == 200 and len(response.text) < 1000:
        vuln = {
            'type': 'INSECURE_ENDPOINT',
            'url': url,
            'issue': 'Low content length',
            'risk_score': RISK_LEVELS['INSECURE_ENDPOINT']
        }
        vulnerabilities.append(vuln)
    elif response.status_code == 403:
        vuln = {
            'type': 'INSECURE_ENDPOINT',
            'url': url,
            'issue': 'Access Forbidden',
            'risk_score': RISK_LEVELS['INSECURE_ENDPOINT']
        }
        vulnerabilities.append(vuln)
    
    return vulnerabilities

def calculate_risk_metrics(vulnerabilities):
    """Calculate risk metrics based on found vulnerabilities"""
    metrics = {
        'total_vulnerabilities': len(vulnerabilities),
        'risk_by_type': {},
        'overall_risk_score': 0,
        'high_risk_count': 0,
        'medium_risk_count': 0,
        'low_risk_count': 0
    }

    # Count vulnerabilities by type
    for vuln in vulnerabilities:
        vuln_type = vuln['type']
        if vuln_type not in metrics['risk_by_type']:
            metrics['risk_by_type'][vuln_type] = 0
        metrics['risk_by_type'][vuln_type] += 1

        # Categorize by risk level
        risk_score = vuln['risk_score']
        if risk_score >= 8:
            metrics['high_risk_count'] += 1
        elif risk_score >= 5:
            metrics['medium_risk_count'] += 1
        else:
            metrics['low_risk_count'] += 1

    # Calculate overall risk score (average)
    if vulnerabilities:
        total_score = sum(vuln['risk_score'] for vuln in vulnerabilities)
        metrics['overall_risk_score'] = round(total_score / len(vulnerabilities), 2)

    return metrics

def generate_report(vulnerabilities, metrics):
    """Generate a JSON report with findings and metrics"""
    report = {
        'scan_time': datetime.now().isoformat(),
        'target_url': base_url,
        'metrics': metrics,
        'vulnerabilities': vulnerabilities
    }

    with open('security_scan_report.json', 'w') as f:
        json.dump(report, f, indent=4)

def scan_web_app():
    setup_logging()
    logging.info(f"Starting security scan of {base_url}")
    
    all_vulnerabilities = []
    
    for endpoint in endpoints:
        url = urljoin(base_url, endpoint)
        print(f"\nScanning {url}...")
        logging.info(f"Scanning endpoint: {endpoint}")

        # Run all tests
        all_vulnerabilities.extend(test_xss(url))
        all_vulnerabilities.extend(test_csrf(url))
        all_vulnerabilities.extend(test_sql_injection(url))
        all_vulnerabilities.extend(test_directory_traversal(url))
        all_vulnerabilities.extend(test_insecure_endpoints(url))

    # Calculate metrics and generate report
    metrics = calculate_risk_metrics(all_vulnerabilities)
    generate_report(all_vulnerabilities, metrics)

    # Print summary
    print("\nScan Summary:")
    print("-" * 50)
    print(f"Total vulnerabilities found: {metrics['total_vulnerabilities']}")
    print(f"High risk vulnerabilities: {metrics['high_risk_count']}")
    print(f"Medium risk vulnerabilities: {metrics['medium_risk_count']}")
    print(f"Low risk vulnerabilities: {metrics['low_risk_count']}")
    print(f"Overall risk score: {metrics['overall_risk_score']}/10")
    print("\nDetailed report saved to 'security_scan_report.json'")

if __name__ == "__main__":
    scan_web_app()