import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import concurrent.futures
import logging
import sys
from typing import List, Dict
import time
import random


class WebSecurityScanner:
    def __init__(self, base_url: str, endpoints: List[str], max_threads: int = 5):
        self.base_url = base_url
        self.endpoints = endpoints
        self.max_threads = max_threads
        self.session = requests.Session()
        self.setup_logging()
        
        # Enhanced payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src='x' onerror='alert(1)'>",
            "javascript:alert(1)",
            "<svg onload='alert(1)'>",
            "'\"><script>alert(1)</script>"
        ]
        
        self.csrf_payloads = [
            {"key": "csrf_token", "value": "dummy_token"},
            {"key": "_token", "value": "invalid_token"},
            {"key": "authenticity_token", "value": "fake_token"}
        ]
        
        self.sql_injection_payloads = [
            "' OR '1'='1",
            "' AND 1=1 --",
            "1' ORDER BY 1--",
            "1' UNION SELECT NULL--",
            "admin' --",
            "1' WAITFOR DELAY '0:0:5'--"
        ]

        self.open_redirect_payloads = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "javascript:alert(1)"
        ]


    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_scan.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def make_request(self, url: str, method: str = 'GET', **kwargs) -> requests.Response:
        try:
            # Add random delay to avoid overwhelming the server
            time.sleep(random.uniform(0.1, 0.5))
            
            # Add common headers
            headers = {
                'User-Agent': 'Security-Scanner-Bot/1.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
            kwargs['headers'] = {**headers, **kwargs.get('headers', {})}
            
            response = self.session.request(method, url, timeout=10, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed for {url}: {str(e)}")
            return None

    def test_xss(self, url: str) -> List[Dict]:
        vulnerabilities = []
        
        for payload in self.xss_payloads:
            response = self.make_request(url, params={'test': payload})
            if response and payload in response.text:
                vuln = {
                    'type': 'XSS',
                    'url': url,
                    'payload': payload,
                    'evidence': 'Payload reflected in response'
                }
                vulnerabilities.append(vuln)
                self.logger.warning(f"XSS vulnerability found: {vuln}")
        
        return vulnerabilities

    def test_csrf(self, url: str) -> List[Dict]:
        vulnerabilities = []
        response = self.make_request(url)
        
        if not response:
            return vulnerabilities

        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            form_url = urljoin(url, action)
            
            # Check for CSRF tokens
            csrf_fields = form.find_all('input', attrs={
                'type': ['hidden'],
                'name': ['csrf_token', '_token', 'authenticity_token']
            })
            
            if not csrf_fields:
                vuln = {
                    'type': 'CSRF',
                    'url': form_url,
                    'method': method,
                    'evidence': 'No CSRF token found in form'
                }
                vulnerabilities.append(vuln)
                self.logger.warning(f"CSRF vulnerability found: {vuln}")
                
        return vulnerabilities

    def test_sql_injection(self, url: str) -> List[Dict]:
        vulnerabilities = []
        
        for payload in self.sql_injection_payloads:
            response = self.make_request(url, params={'search': payload})
            if response:
                # Check for common SQL error messages
                error_patterns = [
                    'sql syntax',
                    'mysql error',
                    'postgresql error',
                    'oracle error',
                    'sqlite error',
                    'database error'
                ]
                
                response_text = response.text.lower()
                for pattern in error_patterns:
                    if pattern in response_text:
                        vuln = {
                            'type': 'SQL Injection',
                            'url': url,
                            'payload': payload,
                            'evidence': f'SQL error pattern found: {pattern}'
                        }
                        vulnerabilities.append(vuln)
                        self.logger.warning(f"SQL Injection vulnerability found: {vuln}")
                        break
                        
        return vulnerabilities
    
    def test_open_redirect(self, url: str) -> List[Dict]:
        vulnerabilities = []
    
        for param in ['url', 'next', 'redirect']:
            for payload in self.open_redirect_payloads:
                response = self.make_request(url, params={param: payload}, allow_redirects=False)
            
                if response and response.status_code == 302 and response.headers.get('Location', '').startswith(payload):
                    vuln = {
                        'type': 'Open Redirect',
                        'url': url,
                        'payload': payload,
                        'evidence': f'Redirects to: {response.headers.get("Location")}'
                    }
                    vulnerabilities.append(vuln)
                    self.logger.warning(f"Open Redirect vulnerability found: {vuln}")
        return vulnerabilities


    def test_insecure_endpoints(self, url: str) -> List[Dict]:
        vulnerabilities = []
        response = self.make_request(url)
        
        if not response:
            return vulnerabilities

        # Test for various security issues
        checks = [
            {
                'condition': response.status_code == 200 and len(response.text) < 1000,
                'type': 'Low Content Length',
                'description': 'Endpoint returns very little content'
            },
            {
                'condition': not response.headers.get('X-Frame-Options'),
                'type': 'Missing X-Frame-Options',
                'description': 'Vulnerable to clickjacking'
            },
            {
                'condition': not response.headers.get('X-Content-Type-Options'),
                'type': 'Missing X-Content-Type-Options',
                'description': 'MIME-sniffing vulnerability'
            },
            {
                'condition': not response.headers.get('Content-Security-Policy'),
                'type': 'Missing CSP',
                'description': 'No Content Security Policy'
            }
        ]
        
        for check in checks:
            if check['condition']:
                vuln = {
                    'type': 'Insecure Configuration',
                    'url': url,
                    'issue': check['type'],
                    'description': check['description']
                }
                vulnerabilities.append(vuln)
                self.logger.warning(f"Security configuration issue found: {vuln}")
                
        return vulnerabilities

    def scan_endpoint(self, endpoint: str) -> Dict:
        url = urljoin(self.base_url, endpoint)
        self.logger.info(f"Scanning endpoint: {url}")
        
        results = {
            'endpoint': endpoint,
            'url': url,
            'vulnerabilities': []
        }
        
        # Run all tests
        results['vulnerabilities'].extend(self.test_xss(url))
        results['vulnerabilities'].extend(self.test_csrf(url))
        results['vulnerabilities'].extend(self.test_sql_injection(url))
        results['vulnerabilities'].extend(self.test_insecure_endpoints(url))
        results['vulnerabilities'].extend(self.test_open_redirect(url))

        
        return results
    
    

    def scan_web_app(self) -> List[Dict]:
        self.logger.info(f"Starting security scan of {self.base_url}")
        start_time = time.time()
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_endpoint = {
                executor.submit(self.scan_endpoint, endpoint): endpoint 
                for endpoint in self.endpoints
            }
            
            for future in concurrent.futures.as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Error scanning endpoint {endpoint}: {str(e)}")
        
        duration = time.time() - start_time
        self.logger.info(f"Scan completed in {duration:.2f} seconds")
        return results
    

def main():
    # Example usage
    base_url = "https://victoryschools.in"
    endpoints = [
        "/",
        "/Victory/Admin/admin_login.php",
        "/Victory/Faculty/faculty_login.php",
        "/Victory/Student/student_login.php",
        "/profile",
        "/admin",
        "/api/users",
        "/api/products",
        "/register",
        "/forgot-password",
        "/settings"
    ]
    '''base_url = "https://localhost/ISM"
    endpoints = [
        "/",
        "/cart.php",
        "/logout.php",
        "/index.php",
        "/password.php",
        "/user_dashboard.php",
        "/register.php",
        "/modify_cart.php",
        "/link.php"
    ]'''
    scanner = WebSecurityScanner(base_url, endpoints)
    results = scanner.scan_web_app()
    
    # Print summary
    print("\nScan Summary:")
    print("-" * 50)
    total_vulnerabilities = sum(len(r['vulnerabilities']) for r in results)
    print(f"Total endpoints scanned: {len(endpoints)}")
    print(f"Total vulnerabilities found: {total_vulnerabilities}")
    
    # Print detailed results
    for result in results:
        if result['vulnerabilities']:
            print(f"\nVulnerabilities for {result['url']}:")
            for vuln in result['vulnerabilities']:
                print(f"- {vuln['type']}: {vuln.get('description', vuln.get('evidence', 'No details'))}")

if __name__ == "__main__":
    main()