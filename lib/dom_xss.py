"""
DOM XSS Detection Module for XSSProbe
Implements client-side DOM-based XSS vulnerability detection

DOM XSS occurs when JavaScript code dynamically writes user input 
to the DOM without proper sanitization.
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from lib.helper.Log import Log
from lib.helper.helper import session

class DOMXSSDetector:
    """
    DOM XSS Detection Engine
    
    Detects DOM-based XSS vulnerabilities by:
    1. Analyzing JavaScript sources that read user input
    2. Identifying dangerous sinks that write to DOM
    3. Testing payloads that trigger DOM manipulation
    4. Simulating client-side execution patterns
    """
    
    def __init__(self):
        # JavaScript sources that can contain user input
        self.dom_sources = [
            'document.URL',
            'document.documentURI', 
            'document.URLUnencoded',
            'document.baseURI',
            'location',
            'location.href',
            'location.search',
            'location.hash',
            'location.pathname',
            'document.cookie',
            'document.referrer',
            'window.name',
            'history.pushState',
            'history.replaceState',
            'localStorage',
            'sessionStorage'
        ]
        
        # Dangerous DOM sinks that can execute JavaScript
        self.dom_sinks = [
            'document.write',
            'document.writeln',
            'innerHTML',
            'outerHTML',
            'insertAdjacentHTML',
            'onevent',
            'eval',
            'setTimeout',
            'setInterval',
            'execScript',
            'crypto.generateCRMFRequest',
            'ScriptElement.src',
            'ScriptElement.text',
            'ScriptElement.textContent',
            'ScriptElement.innerText',
            'location',
            'location.href',
            'location.replace',
            'location.assign',
            'history.pushState',
            'history.replaceState'
        ]
        
        # DOM XSS test payloads
        self.dom_payloads = [
            # Hash-based payloads
            "#<script>alert('DOM_XSS')</script>",
            "#<img src=x onerror=alert('DOM_XSS')>",
            "#<svg onload=alert('DOM_XSS')>",
            
            # JavaScript protocol
            "javascript:alert('DOM_XSS')",
            
            # Event handler payloads
            "#onmouseover=alert('DOM_XSS')",
            "#'><script>alert('DOM_XSS')</script>",
            
            # URL parameter simulation
            "?param=<script>alert('DOM_XSS')</script>",
            
            # Advanced DOM payloads
            "#<iframe src=javascript:alert('DOM_XSS')>",
            "#<object data=javascript:alert('DOM_XSS')>",
            "#<embed src=javascript:alert('DOM_XSS')>",
            
            # AngularJS template injection
            "#{{constructor.constructor('alert(\"DOM_XSS\")')()}}",
            
            # React XSS patterns
            "#<div dangerouslySetInnerHTML={{__html: '<script>alert(\"DOM_XSS\")</script>'}} />",
        ]

    def detect_dom_sources_and_sinks(self, html_content, js_content=""):
        """
        Analyze HTML and JavaScript for DOM sources and sinks
        
        Args:
            html_content (str): HTML content to analyze
            js_content (str): Additional JavaScript content
            
        Returns:
            dict: Found sources and sinks
        """
        found_sources = []
        found_sinks = []
        
        # Combine HTML and JS content for analysis
        content = html_content + " " + js_content
        
        # Check for DOM sources
        for source in self.dom_sources:
            if re.search(r'\b' + re.escape(source) + r'\b', content, re.IGNORECASE):
                found_sources.append(source)
                
        # Check for DOM sinks  
        for sink in self.dom_sinks:
            if re.search(r'\b' + re.escape(sink) + r'\b', content, re.IGNORECASE):
                found_sinks.append(sink)
                
        return {
            'sources': found_sources,
            'sinks': found_sinks,
            'potential_dom_xss': len(found_sources) > 0 and len(found_sinks) > 0
        }

    def extract_javascript(self, html_content):
        """
        Extract JavaScript code from HTML content
        
        Args:
            html_content (str): HTML content
            
        Returns:
            str: Extracted JavaScript code
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        js_code = ""
        
        # Extract inline JavaScript
        for script in soup.find_all('script'):
            if script.string:
                js_code += script.string + "\n"
                
        # Extract event handlers
        for tag in soup.find_all():
            for attr in tag.attrs:
                if attr.startswith('on'):  # onclick, onload, etc.
                    js_code += tag.attrs[attr] + "\n"
                    
        return js_code

    def analyze_javascript_patterns(self, js_content):
        """
        Analyze JavaScript for DOM XSS vulnerability patterns
        
        Args:
            js_content (str): JavaScript content to analyze
            
        Returns:
            list: List of potential vulnerabilities found
        """
        vulnerabilities = []
        
        # Pattern 1: Direct location.hash usage
        if re.search(r'location\.hash.*innerHTML|document\.write.*location\.hash', js_content, re.IGNORECASE):
            vulnerabilities.append({
                'type': 'DOM XSS',
                'pattern': 'location.hash to innerHTML/document.write',
                'severity': 'HIGH',
                'description': 'Direct use of location.hash in DOM manipulation'
            })
            
        # Pattern 2: URL parameter to DOM
        if re.search(r'document\.URL.*innerHTML|window\.location.*innerHTML', js_content, re.IGNORECASE):
            vulnerabilities.append({
                'type': 'DOM XSS', 
                'pattern': 'URL to innerHTML',
                'severity': 'HIGH',
                'description': 'URL content directly inserted into DOM'
            })
            
        # Pattern 3: Eval with user input
        if re.search(r'eval.*location\.|eval.*document\.URL', js_content, re.IGNORECASE):
            vulnerabilities.append({
                'type': 'DOM XSS',
                'pattern': 'eval() with user input',
                'severity': 'CRITICAL', 
                'description': 'eval() function using user-controlled input'
            })
            
        # Pattern 4: setTimeout/setInterval with user input
        if re.search(r'setTimeout.*location\.|setInterval.*document\.URL', js_content, re.IGNORECASE):
            vulnerabilities.append({
                'type': 'DOM XSS',
                'pattern': 'setTimeout/setInterval with user input',
                'severity': 'HIGH',
                'description': 'Timer functions with user-controlled input'
            })
            
        return vulnerabilities

    def test_dom_xss_payloads(self, target_url, session_obj):
        """
        Test DOM XSS payloads against target URL
        
        Args:
            target_url (str): Target URL to test
            session_obj: Requests session object
            
        Returns:
            list: List of successful DOM XSS tests
        """
        successful_tests = []
        
        for payload in self.dom_payloads:
            try:
                # Test hash-based payloads
                if payload.startswith('#'):
                    test_url = target_url + payload
                # Test parameter-based payloads  
                elif payload.startswith('?'):
                    separator = '&' if '?' in target_url else '?'
                    test_url = target_url + separator + payload[1:]
                else:
                    test_url = target_url + '#' + payload
                    
                Log.info(f"Testing DOM XSS payload: {payload}")
                
                response = session_obj.get(test_url)
                
                # Analyze response for DOM XSS indicators
                if self._check_dom_xss_response(response.text, payload):
                    successful_tests.append({
                        'url': test_url,
                        'payload': payload,
                        'method': 'DOM',
                        'type': 'DOM XSS'
                    })
                    Log.high(f"Potential DOM XSS found: {test_url}")
                    
            except Exception as e:
                Log.info(f"Error testing DOM payload {payload}: {str(e)}")
                continue
                
        return successful_tests

    def _check_dom_xss_response(self, response_text, payload):
        """
        Check if response indicates potential DOM XSS
        
        Args:
            response_text (str): HTTP response content
            payload (str): Payload that was tested
            
        Returns:
            bool: True if DOM XSS indicators found
        """
        # Extract JavaScript from response
        js_content = self.extract_javascript(response_text)
        
        # Check if payload appears in JavaScript context
        if payload.replace('#', '').replace('?param=', '') in js_content:
            return True
            
        # Check for reflection in dangerous contexts
        dangerous_contexts = [
            r'document\.write\s*\(\s*["\'][^"\']*' + re.escape(payload),
            r'innerHTML\s*=\s*["\'][^"\']*' + re.escape(payload),
            r'location\.href\s*=\s*["\'][^"\']*' + re.escape(payload)
        ]
        
        for context in dangerous_contexts:
            if re.search(context, response_text, re.IGNORECASE):
                return True
                
        return False

    def generate_dom_xss_report(self, url, findings):
        """
        Generate detailed DOM XSS vulnerability report
        
        Args:
            url (str): Target URL
            findings (dict): DOM XSS analysis findings
            
        Returns:
            str: Formatted report
        """
        report = f"\n{'='*60}\n"
        report += f"DOM XSS Analysis Report for: {url}\n"
        report += f"{'='*60}\n\n"
        
        if findings.get('sources'):
            report += "🔍 DOM Sources Found:\n"
            for source in findings['sources']:
                report += f"  • {source}\n"
            report += "\n"
            
        if findings.get('sinks'):
            report += "⚠️  DOM Sinks Found:\n" 
            for sink in findings['sinks']:
                report += f"  • {sink}\n"
            report += "\n"
            
        if findings.get('vulnerabilities'):
            report += "🚨 Potential DOM XSS Vulnerabilities:\n"
            for vuln in findings['vulnerabilities']:
                report += f"  • Type: {vuln['type']}\n"
                report += f"    Pattern: {vuln['pattern']}\n"
                report += f"    Severity: {vuln['severity']}\n"
                report += f"    Description: {vuln['description']}\n\n"
                
        if findings.get('successful_tests'):
            report += "✅ Confirmed DOM XSS:\n"
            for test in findings['successful_tests']:
                report += f"  • URL: {test['url']}\n"
                report += f"    Payload: {test['payload']}\n"
                report += f"    Method: {test['method']}\n\n"
                
        return report

    def scan_for_dom_xss(self, target_url, proxy=None, headers=None, cookie=None):
        """
        Main DOM XSS scanning function
        
        Args:
            target_url (str): URL to scan for DOM XSS
            proxy: Proxy configuration
            headers: HTTP headers
            cookie: Cookie string
            
        Returns:
            dict: Complete DOM XSS analysis results
        """
        Log.info("Starting DOM XSS vulnerability scan...")
        
        try:
            # Handle None values for session creation
            if headers is None:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            if cookie is None:
                cookie = '{"session":"test"}'  # Default cookie
                
            # Create session
            session_obj = session(proxy, headers, cookie)
            
            # Get initial page content
            response = session_obj.get(target_url)
            html_content = response.text
            
            # Extract JavaScript
            js_content = self.extract_javascript(html_content)
            
            # Analyze for sources and sinks
            Log.info("Analyzing DOM sources and sinks...")
            dom_analysis = self.detect_dom_sources_and_sinks(html_content, js_content)
            
            # Analyze JavaScript patterns
            Log.info("Analyzing JavaScript patterns...")
            js_vulnerabilities = self.analyze_javascript_patterns(js_content)
            
            # Test DOM XSS payloads
            Log.info("Testing DOM XSS payloads...")
            successful_tests = self.test_dom_xss_payloads(target_url, session_obj)
            
            # Compile results
            findings = {
                'url': target_url,
                'sources': dom_analysis['sources'],
                'sinks': dom_analysis['sinks'],
                'potential_dom_xss': dom_analysis['potential_dom_xss'],
                'vulnerabilities': js_vulnerabilities,
                'successful_tests': successful_tests,
                'has_dom_xss': len(successful_tests) > 0 or len(js_vulnerabilities) > 0
            }
            
            # Generate and log report
            report = self.generate_dom_xss_report(target_url, findings)
            Log.info("DOM XSS scan completed")
            
            # Save results if vulnerabilities found
            if findings['has_dom_xss']:
                with open("dom_xss_results.txt", "a") as f:
                    f.write(report)
                    f.write("\n" + "="*60 + "\n")
                    
            return findings
            
        except Exception as e:
            Log.high(f"Error during DOM XSS scan: {str(e)}")
            return {'error': str(e), 'has_dom_xss': False}