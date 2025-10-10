"""
Authenticated Scanner Mode for XSSProbe
Handles authentication and session management for protected areas
"""

import requests
import json
import re
import time
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import base64
import hashlib


class AuthenticatedScanner:
    """
    Scanner for authenticated areas with session management
    """
    
    def __init__(self, session: requests.Session = None, config: Dict[str, Any] = None):
        self.session = session or requests.Session()
        self.config = config or self._get_default_config()
        self.authenticated = False
        self.auth_tokens = {}
        self.session_cookies = {}
        self.csrf_tokens = {}
        self.results = []
        
    def _get_default_config(self) -> Dict[str, Any]:
        """Default authentication configuration"""
        return {
            "login_indicators": [
                "login", "signin", "auth", "account", "user"
            ],
            "logout_indicators": [
                "logout", "signout", "exit", "disconnect"
            ],
            "protected_indicators": [
                "dashboard", "admin", "profile", "settings", "private"
            ],
            "session_timeout": 3600,  # 1 hour
            "max_login_attempts": 3,
            "csrf_token_names": [
                "csrf_token", "authenticity_token", "_token", 
                "csrfmiddlewaretoken", "csrf", "_csrf"
            ],
            "common_auth_headers": [
                "Authorization", "X-Auth-Token", "X-API-Key", 
                "Authentication", "Bearer"
            ],
            "request_timeout": 30
        }
    
    def authenticate_basic(self, username: str, password: str, 
                          login_url: str = None) -> bool:
        """
        Perform basic authentication
        
        Args:
            username: Username for authentication
            password: Password for authentication
            login_url: Optional login URL (will auto-discover if not provided)
        
        Returns:
            True if authentication successful
        """
        print(f"[AUTH] Attempting basic authentication for user: {username}")
        
        if not login_url:
            login_url = self._discover_login_url()
            if not login_url:
                print("[AUTH] Could not discover login URL")
                return False
        
        # Get login form
        login_form = self._get_login_form(login_url)
        if not login_form:
            print("[AUTH] Could not find login form")
            return False
        
        # Fill and submit login form
        success = self._submit_login_form(login_form, username, password)
        
        if success:
            self.authenticated = True
            print("[AUTH] ✅ Authentication successful")
            return True
        else:
            print("[AUTH] ❌ Authentication failed")
            return False
    
    def authenticate_bearer_token(self, token: str, header_name: str = "Authorization") -> bool:
        """
        Authenticate using Bearer token
        
        Args:
            token: Bearer token
            header_name: Header name for token
        
        Returns:
            True if authentication successful
        """
        print(f"[AUTH] Setting up Bearer token authentication")
        
        # Format token properly
        if not token.startswith("Bearer "):
            token = f"Bearer {token}"
        
        self.session.headers[header_name] = token
        self.authenticated = True
        
        print("[AUTH] ✅ Bearer token authentication configured")
        return True
    
    def authenticate_api_key(self, api_key: str, 
                           header_name: str = "X-API-Key") -> bool:
        """
        Authenticate using API key
        
        Args:
            api_key: API key
            header_name: Header name for API key
        
        Returns:
            True if authentication successful
        """
        print(f"[AUTH] Setting up API key authentication")
        
        self.session.headers[header_name] = api_key
        self.authenticated = True
        
        print("[AUTH] ✅ API key authentication configured")
        return True
    
    def authenticate_cookie(self, cookies: Dict[str, str]) -> bool:
        """
        Authenticate using session cookies
        
        Args:
            cookies: Dictionary of cookie name-value pairs
        
        Returns:
            True if authentication successful
        """
        print(f"[AUTH] Setting up cookie-based authentication")
        
        for name, value in cookies.items():
            self.session.cookies.set(name, value)
        
        self.session_cookies.update(cookies)
        self.authenticated = True
        
        print("[AUTH] ✅ Cookie authentication configured")
        return True
    
    def scan_authenticated_areas(self, base_url: str, 
                               payloads: List[str],
                               depth: int = 3) -> List[Dict]:
        """
        Scan authenticated areas for XSS vulnerabilities
        
        Args:
            base_url: Base URL to scan
            payloads: XSS payloads to test
            depth: Maximum crawling depth
        
        Returns:
            List of vulnerability findings
        """
        if not self.authenticated:
            print("[AUTH] ⚠️ Not authenticated - scanning may be limited")
        
        print(f"[AUTH] Starting authenticated scan of {base_url}")
        
        # Discover authenticated pages
        auth_pages = self._discover_authenticated_pages(base_url, depth)
        print(f"[AUTH] Found {len(auth_pages)} authenticated pages")
        
        # Test each page for XSS
        for page_url in auth_pages:
            self._test_authenticated_page(page_url, payloads)
        
        return self.results
    
    def _discover_login_url(self) -> Optional[str]:
        """Auto-discover login URL"""
        # This would need a base URL to work from
        # For now, return None - would need to be called with a base URL
        return None
    
    def _get_login_form(self, login_url: str) -> Optional[Dict]:
        """
        Extract login form from login page
        
        Args:
            login_url: URL of login page
        
        Returns:
            Dictionary containing form information
        """
        try:
            response = self.session.get(login_url, timeout=self.config["request_timeout"])
            if response.status_code != 200:
                return None
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find login form
            forms = soup.find_all('form')
            login_form = None
            
            for form in forms:
                form_text = str(form).lower()
                if any(indicator in form_text for indicator in self.config["login_indicators"]):
                    login_form = form
                    break
            
            if not login_form:
                # If no obvious login form, take the first form
                login_form = forms[0] if forms else None
            
            if not login_form:
                return None
            
            # Extract form details
            action = login_form.get('action', login_url)
            method = login_form.get('method', 'POST').upper()
            
            # Get form inputs
            inputs = {}
            username_field = None
            password_field = None
            
            for input_tag in login_form.find_all(['input', 'textarea']):
                name = input_tag.get('name')
                input_type = input_tag.get('type', 'text').lower()
                value = input_tag.get('value', '')
                
                if name:
                    inputs[name] = value
                    
                    # Identify username/password fields
                    if input_type == 'password':
                        password_field = name
                    elif (not username_field and 
                          any(term in name.lower() for term in ['user', 'email', 'login'])):
                        username_field = name
            
            # Extract CSRF tokens
            csrf_token = self._extract_csrf_token(login_form, response.text)
            if csrf_token:
                inputs.update(csrf_token)
            
            return {
                'action': urljoin(login_url, action),
                'method': method,
                'inputs': inputs,
                'username_field': username_field,
                'password_field': password_field
            }
            
        except Exception as e:
            print(f"[AUTH] Error getting login form: {e}")
            return None
    
    def _extract_csrf_token(self, form: BeautifulSoup, 
                           page_content: str) -> Dict[str, str]:
        """Extract CSRF tokens from form or page"""
        tokens = {}
        
        # Check form inputs for CSRF tokens
        for input_tag in form.find_all('input', {'type': 'hidden'}):
            name = input_tag.get('name', '').lower()
            value = input_tag.get('value', '')
            
            if any(csrf_name in name for csrf_name in self.config["csrf_token_names"]):
                tokens[input_tag.get('name')] = value
        
        # Check meta tags for CSRF tokens
        soup = BeautifulSoup(page_content, 'html.parser')
        for meta_tag in soup.find_all('meta'):
            name = meta_tag.get('name', '').lower()
            content = meta_tag.get('content', '')
            
            if any(csrf_name in name for csrf_name in self.config["csrf_token_names"]):
                tokens[meta_tag.get('name')] = content
        
        # Check for CSRF tokens in script tags (common in SPAs)
        for script_tag in soup.find_all('script'):
            script_content = script_tag.get_text()
            for csrf_name in self.config["csrf_token_names"]:
                pattern = rf'{csrf_name}["\']?\s*[:=]\s*["\']([^"\']+)["\']'
                match = re.search(pattern, script_content, re.IGNORECASE)
                if match:
                    tokens[csrf_name] = match.group(1)
        
        return tokens
    
    def _submit_login_form(self, login_form: Dict, 
                          username: str, password: str) -> bool:
        """
        Submit login form with credentials
        
        Args:
            login_form: Form information dictionary
            username: Username
            password: Password
        
        Returns:
            True if login successful
        """
        try:
            # Prepare form data
            form_data = login_form['inputs'].copy()
            
            # Set username and password
            if login_form['username_field']:
                form_data[login_form['username_field']] = username
            if login_form['password_field']:
                form_data[login_form['password_field']] = password
            
            # Submit form
            if login_form['method'] == 'POST':
                response = self.session.post(
                    login_form['action'],
                    data=form_data,
                    timeout=self.config["request_timeout"],
                    allow_redirects=True
                )
            else:
                response = self.session.get(
                    login_form['action'],
                    params=form_data,
                    timeout=self.config["request_timeout"],
                    allow_redirects=True
                )
            
            # Check if login was successful
            return self._check_login_success(response)
            
        except Exception as e:
            print(f"[AUTH] Error submitting login form: {e}")
            return False
    
    def _check_login_success(self, response: requests.Response) -> bool:
        """
        Check if login was successful based on response
        
        Args:
            response: Response from login attempt
        
        Returns:
            True if login successful
        """
        # Check for redirect to dashboard/home page
        if response.history:
            final_url = response.url.lower()
            if any(indicator in final_url for indicator in self.config["protected_indicators"]):
                return True
        
        # Check response content for success indicators
        content = response.text.lower()
        
        # Negative indicators (login failed)
        failure_indicators = [
            "invalid", "incorrect", "failed", "error", "denied",
            "wrong", "bad", "unauthorized"
        ]
        
        if any(indicator in content for indicator in failure_indicators):
            return False
        
        # Positive indicators (login successful)
        success_indicators = [
            "welcome", "dashboard", "logged in", "successful",
            "home", "profile", "account"
        ]
        
        if any(indicator in content for indicator in success_indicators):
            return True
        
        # Check for absence of login form (might indicate success)
        soup = BeautifulSoup(response.text, 'html.parser')
        login_forms = []
        
        for form in soup.find_all('form'):
            form_text = str(form).lower()
            if any(indicator in form_text for indicator in self.config["login_indicators"]):
                login_forms.append(form)
        
        # If no login forms found, might be logged in
        if not login_forms:
            return True
        
        # Default to failed if unclear
        return False
    
    def _discover_authenticated_pages(self, base_url: str, 
                                    max_depth: int) -> List[str]:
        """
        Discover pages that require authentication
        
        Args:
            base_url: Base URL to start crawling
            max_depth: Maximum crawling depth
        
        Returns:
            List of authenticated page URLs
        """
        authenticated_pages = []
        visited = set()
        to_visit = [(base_url, 0)]
        
        while to_visit:
            url, depth = to_visit.pop(0)
            
            if depth > max_depth or url in visited:
                continue
            
            visited.add(url)
            
            try:
                response = self.session.get(url, timeout=self.config["request_timeout"])
                
                # Check if page requires authentication
                if self._is_authenticated_page(response):
                    authenticated_pages.append(url)
                
                # Extract links for further crawling
                if depth < max_depth:
                    links = self._extract_links(response.text, url)
                    for link in links:
                        if link not in visited:
                            to_visit.append((link, depth + 1))
                
            except Exception as e:
                print(f"[AUTH] Error accessing {url}: {e}")
                continue
        
        return authenticated_pages
    
    def _is_authenticated_page(self, response: requests.Response) -> bool:
        """Check if page requires authentication"""
        # Check status code
        if response.status_code == 401:
            return False  # Unauthorized - not accessible
        
        if response.status_code == 403:
            return False  # Forbidden - might need higher privileges
        
        # Check URL for protected areas
        url_lower = response.url.lower()
        if any(indicator in url_lower for indicator in self.config["protected_indicators"]):
            return True
        
        # Check content for authentication indicators
        content = response.text.lower()
        
        # If we see login forms, we might not be authenticated
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            form_text = str(form).lower()
            if any(indicator in form_text for indicator in self.config["login_indicators"]):
                return False  # Found login form, probably not authenticated
        
        # Look for authenticated content indicators
        auth_content_indicators = [
            "welcome", "dashboard", "profile", "logout", "admin",
            "settings", "account", "my account"
        ]
        
        if any(indicator in content for indicator in auth_content_indicators):
            return True
        
        return False
    
    def _extract_links(self, html_content: str, base_url: str) -> List[str]:
        """Extract links from HTML content"""
        links = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            for link_tag in soup.find_all('a', href=True):
                href = link_tag['href']
                absolute_url = urljoin(base_url, href)
                
                # Filter out external links and common non-page resources
                parsed_base = urlparse(base_url)
                parsed_link = urlparse(absolute_url)
                
                if (parsed_link.netloc == parsed_base.netloc and
                    not any(ext in absolute_url.lower() for ext in 
                           ['.css', '.js', '.png', '.jpg', '.gif', '.pdf'])):
                    links.append(absolute_url)
        
        except Exception as e:
            print(f"[AUTH] Error extracting links: {e}")
        
        return links
    
    def _test_authenticated_page(self, page_url: str, payloads: List[str]):
        """
        Test an authenticated page for XSS vulnerabilities
        
        Args:
            page_url: URL of page to test
            payloads: XSS payloads to test
        """
        print(f"[AUTH] Testing authenticated page: {page_url}")
        
        try:
            # Get page and analyze forms/inputs
            response = self.session.get(page_url, timeout=self.config["request_timeout"])
            if response.status_code != 200:
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Test forms
            for form in soup.find_all('form'):
                self._test_authenticated_form(form, page_url, payloads)
            
            # Test URL parameters if any
            parsed_url = urlparse(page_url)
            if parsed_url.query:
                self._test_url_parameters(page_url, payloads)
            
        except Exception as e:
            print(f"[AUTH] Error testing authenticated page {page_url}: {e}")
    
    def _test_authenticated_form(self, form: BeautifulSoup, 
                                page_url: str, payloads: List[str]):
        """Test form inputs for XSS vulnerabilities"""
        try:
            action = form.get('action', page_url)
            method = form.get('method', 'GET').upper()
            action_url = urljoin(page_url, action)
            
            # Get form inputs
            inputs = {}
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name and input_tag.get('type') != 'submit':
                    inputs[name] = input_tag.get('value', 'test')
            
            if not inputs:
                return
            
            # Extract CSRF tokens
            csrf_tokens = self._extract_csrf_token(form, str(form))
            inputs.update(csrf_tokens)
            
            # Test each input with each payload
            for input_name in inputs:
                if input_name in csrf_tokens:
                    continue  # Skip CSRF tokens
                
                for payload in payloads:
                    test_data = inputs.copy()
                    test_data[input_name] = payload
                    
                    vulnerability = self._test_authenticated_payload(
                        action_url, method, test_data, input_name, payload
                    )
                    
                    if vulnerability:
                        self.results.append(vulnerability)
                        print(f"[AUTH] 🚨 XSS found in {input_name} at {action_url}")
        
        except Exception as e:
            print(f"[AUTH] Error testing form: {e}")
    
    def _test_url_parameters(self, page_url: str, payloads: List[str]):
        """Test URL parameters for XSS vulnerabilities"""
        try:
            parsed_url = urlparse(page_url)
            params = parse_qs(parsed_url.query)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            for param_name, param_values in params.items():
                for payload in payloads:
                    test_params = {k: v[0] if v else '' for k, v in params.items()}
                    test_params[param_name] = payload
                    
                    vulnerability = self._test_authenticated_payload(
                        base_url, 'GET', test_params, param_name, payload
                    )
                    
                    if vulnerability:
                        self.results.append(vulnerability)
                        print(f"[AUTH] 🚨 XSS found in parameter {param_name}")
        
        except Exception as e:
            print(f"[AUTH] Error testing URL parameters: {e}")
    
    def _test_authenticated_payload(self, url: str, method: str, 
                                  data: Dict, param_name: str, 
                                  payload: str) -> Optional[Dict]:
        """Test a single payload in authenticated context"""
        try:
            # Make request
            if method == 'POST':
                response = self.session.post(
                    url, 
                    data=data, 
                    timeout=self.config["request_timeout"]
                )
            else:
                response = self.session.get(
                    url, 
                    params=data, 
                    timeout=self.config["request_timeout"]
                )
            
            # Check for XSS indicators
            if self._check_xss_reflection(response.text, payload):
                return {
                    'type': 'xss',
                    'severity': 'high',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'method': method,
                    'authenticated': True,
                    'response_snippet': response.text[:500],
                    'status_code': response.status_code
                }
        
        except Exception as e:
            print(f"[AUTH] Error testing payload: {e}")
        
        return None
    
    def _check_xss_reflection(self, response_text: str, payload: str) -> bool:
        """Check if payload is reflected in response"""
        # Direct reflection
        if payload in response_text:
            return True
        
        # Check for decoded versions
        import html
        from urllib.parse import unquote
        
        decoded_variants = [
            html.unescape(payload),
            unquote(payload),
            unquote(unquote(payload))
        ]
        
        for variant in decoded_variants:
            if variant in response_text:
                return True
        
        return False
    
    def check_session_validity(self) -> bool:
        """Check if current session is still valid"""
        if not self.authenticated:
            return False
        
        # This would require a test endpoint or checking session cookies
        # For now, assume session is valid if we have cookies
        return bool(self.session.cookies)
    
    def renew_session(self) -> bool:
        """Attempt to renew the session"""
        # Implementation would depend on the specific authentication method
        # For now, just return current status
        return self.authenticated
    
    def logout(self) -> bool:
        """Logout from current session"""
        try:
            # Clear session data
            self.session.cookies.clear()
            self.session.headers.clear()
            self.authenticated = False
            self.auth_tokens.clear()
            self.session_cookies.clear()
            self.csrf_tokens.clear()
            
            print("[AUTH] ✅ Logged out successfully")
            return True
        
        except Exception as e:
            print(f"[AUTH] Error during logout: {e}")
            return False
    
    def generate_auth_report(self) -> Dict:
        """Generate authentication scan report"""
        return {
            'scan_type': 'authenticated',
            'authenticated': self.authenticated,
            'session_valid': self.check_session_validity(),
            'total_vulnerabilities': len(self.results),
            'vulnerabilities': self.results,
            'auth_config': self.config,
            'scan_timestamp': time.time()
        }


# Example usage
if __name__ == "__main__":
    # Initialize authenticated scanner
    auth_scanner = AuthenticatedScanner()
    
    # Example: Basic authentication
    login_success = auth_scanner.authenticate_basic(
        username="admin",
        password="password123",
        login_url="https://example.com/login"
    )
    
    if login_success:
        # Test payloads
        test_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>"
        ]
        
        # Scan authenticated areas
        results = auth_scanner.scan_authenticated_areas(
            "https://example.com",
            test_payloads,
            depth=2
        )
        
        # Generate report
        report = auth_scanner.generate_auth_report()
        print(f"Authenticated scan completed. Found {len(results)} vulnerabilities.")
        
        # Logout
        auth_scanner.logout()
    else:
        print("Authentication failed")