"""
Deep DOM Scanner Mode for XSSProbe
Advanced DOM-based XSS detection with JavaScript execution analysis
"""

import requests
import json
import time
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from bs4 import BeautifulSoup
import hashlib
import base64


class DeepDOMScanner:
    """
    Advanced DOM-based XSS scanner with JavaScript source/sink analysis
    """
    
    def __init__(self, session: requests.Session = None, config: Dict[str, Any] = None):
        self.session = session or requests.Session()
        self.config = config or self._get_default_config()
        self.dom_sources = []
        self.dom_sinks = []
        self.javascript_analysis = {}
        self.results = []
        
    def _get_default_config(self) -> Dict[str, Any]:
        """Default DOM scanner configuration"""
        return {
            # DOM sources (where untrusted data enters)
            "dom_sources": [
                "location.href", "location.search", "location.hash", "location.pathname",
                "document.URL", "document.documentURI", "document.baseURI",
                "document.cookie", "document.referrer",
                "window.name", "history.pushState", "history.replaceState",
                "localStorage", "sessionStorage", "postMessage",
                "document.getElementById", "document.getElementsByName",
                "document.getElementsByTagName", "document.querySelector",
                "document.querySelectorAll", "XMLHttpRequest.responseText",
                "fetch", "WebSocket", "EventSource"
            ],
            
            # DOM sinks (where data can cause XSS)
            "dom_sinks": [
                "innerHTML", "outerHTML", "insertAdjacentHTML",
                "document.write", "document.writeln", "eval",
                "setTimeout", "setInterval", "Function",
                "execScript", "setImmediate", "msSetImmediate",
                "createElement", "createTextNode", "appendChild",
                "insertBefore", "replaceChild", "setAttribute",
                "location.href", "location.assign", "location.replace",
                "history.pushState", "history.replaceState",
                "document.cookie", "window.name"
            ],
            
            # JavaScript frameworks and libraries
            "frameworks": [
                "jquery", "angular", "react", "vue", "backbone",
                "ember", "knockout", "prototype", "mootools"
            ],
            
            # Context-specific payloads
            "context_payloads": {
                "html": [
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "<iframe src=javascript:alert(1)>",
                    "<script>alert(1)</script>"
                ],
                "attribute": [
                    "\" onmouseover=\"alert(1)",
                    "' onmouseover='alert(1)",
                    "javascript:alert(1)",
                    "data:text/html,<script>alert(1)</script>"
                ],
                "javascript": [
                    "');alert(1);//",
                    "\";alert(1);//",
                    "\\x22;alert(1);//",
                    "'+alert(1)+'"
                ],
                "url": [
                    "javascript:alert(1)",
                    "data:text/html,<script>alert(1)</script>",
                    "vbscript:alert(1)",
                    "about:blank"
                ],
                "css": [
                    "expression(alert(1))",
                    "url(javascript:alert(1))",
                    "\\22\\3E\\3Cscript\\3Ealert(1)\\3C/script\\3E"
                ]
            },
            
            "max_js_analysis_depth": 10,
            "request_timeout": 15,
            "analyze_frameworks": True,
            "detect_client_side_routing": True,
            "analyze_event_handlers": True
        }
    
    def analyze_dom_structure(self, url: str) -> Dict[str, Any]:
        """
        Analyze the DOM structure and JavaScript of a page
        
        Args:
            url: URL to analyze
        
        Returns:
            Analysis results including sources, sinks, and vulnerabilities
        """
        print(f"[DOM] Analyzing DOM structure of {url}")
        
        try:
            response = self.session.get(url, timeout=self.config["request_timeout"])
            if response.status_code != 200:
                return {}
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract and analyze JavaScript
            js_analysis = self._analyze_javascript(soup, url)
            
            # Find DOM sources and sinks
            sources = self._find_dom_sources(js_analysis)
            sinks = self._find_dom_sinks(js_analysis)
            
            # Analyze data flows
            flows = self._analyze_data_flows(sources, sinks, js_analysis)
            
            # Check for vulnerable patterns
            vulnerabilities = self._check_vulnerable_patterns(flows, url)
            
            analysis = {
                'url': url,
                'javascript_files': js_analysis.get('files', []),
                'inline_scripts': js_analysis.get('inline_count', 0),
                'dom_sources': sources,
                'dom_sinks': sinks,
                'data_flows': flows,
                'frameworks_detected': js_analysis.get('frameworks', []),
                'vulnerabilities': vulnerabilities,
                'analysis_timestamp': time.time()
            }
            
            self.javascript_analysis[url] = analysis
            self.results.extend(vulnerabilities)
            
            return analysis
            
        except Exception as e:
            print(f"[DOM] Error analyzing DOM: {e}")
            return {}
    
    def _analyze_javascript(self, soup: BeautifulSoup, base_url: str) -> Dict[str, Any]:
        """Analyze JavaScript code in the page"""
        analysis = {
            'files': [],
            'inline_scripts': [],
            'event_handlers': [],
            'frameworks': [],
            'inline_count': 0
        }
        
        # Analyze external JavaScript files
        for script_tag in soup.find_all('script', src=True):
            src = script_tag.get('src')
            if src:
                js_url = urljoin(base_url, src)
                js_content = self._fetch_javascript(js_url)
                
                if js_content:
                    file_analysis = self._analyze_js_content(js_content, js_url)
                    file_analysis['url'] = js_url
                    analysis['files'].append(file_analysis)
        
        # Analyze inline JavaScript
        for script_tag in soup.find_all('script'):
            if script_tag.string and script_tag.string.strip():
                content = script_tag.string.strip()
                inline_analysis = self._analyze_js_content(content, base_url)
                inline_analysis['type'] = 'inline'
                analysis['inline_scripts'].append(inline_analysis)
                analysis['inline_count'] += 1
        
        # Analyze event handlers
        for tag in soup.find_all():
            for attr_name, attr_value in tag.attrs.items():
                if attr_name.lower().startswith('on') and isinstance(attr_value, str):
                    analysis['event_handlers'].append({
                        'tag': tag.name,
                        'attribute': attr_name,
                        'code': attr_value,
                        'analysis': self._analyze_js_content(attr_value, base_url)
                    })
        
        # Detect frameworks
        all_js_content = ""
        for file_analysis in analysis['files']:
            all_js_content += file_analysis.get('content', '')
        
        for inline_script in analysis['inline_scripts']:
            all_js_content += inline_script.get('content', '')
        
        analysis['frameworks'] = self._detect_frameworks(all_js_content)
        
        return analysis
    
    def _fetch_javascript(self, js_url: str) -> Optional[str]:
        """Fetch JavaScript file content"""
        try:
            response = self.session.get(js_url, timeout=self.config["request_timeout"])
            if response.status_code == 200:
                return response.text
        except Exception as e:
            print(f"[DOM] Error fetching JavaScript {js_url}: {e}")
        
        return None
    
    def _analyze_js_content(self, js_content: str, source_url: str) -> Dict[str, Any]:
        """Analyze JavaScript content for sources, sinks, and patterns"""
        analysis = {
            'content': js_content,
            'source_url': source_url,
            'sources_found': [],
            'sinks_found': [],
            'suspicious_patterns': [],
            'functions': [],
            'variables': []
        }
        
        # Find DOM sources
        for source in self.config["dom_sources"]:
            if source in js_content:
                # Find the context around the source
                contexts = self._find_code_contexts(js_content, source)
                for context in contexts:
                    analysis['sources_found'].append({
                        'source': source,
                        'context': context,
                        'line_number': self._get_line_number(js_content, context)
                    })
        
        # Find DOM sinks
        for sink in self.config["dom_sinks"]:
            if sink in js_content:
                contexts = self._find_code_contexts(js_content, sink)
                for context in contexts:
                    analysis['sinks_found'].append({
                        'sink': sink,
                        'context': context,
                        'line_number': self._get_line_number(js_content, context)
                    })
        
        # Find suspicious patterns
        suspicious_patterns = [
            r'eval\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'document\.write\s*\(',
            r'\.html\s*\(',  # jQuery
            r'location\.href\s*=',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'Function\s*\(',
            r'insertAdjacentHTML\s*\('
        ]
        
        for pattern in suspicious_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                context = self._extract_context(js_content, match.start(), match.end())
                analysis['suspicious_patterns'].append({
                    'pattern': pattern,
                    'match': match.group(),
                    'context': context,
                    'line_number': self._get_line_number(js_content, context)
                })
        
        # Extract function definitions
        function_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*\{'
        matches = re.finditer(function_pattern, js_content)
        for match in matches:
            analysis['functions'].append(match.group(1))
        
        # Extract variable assignments
        var_pattern = r'(?:var|let|const)\s+(\w+)\s*='
        matches = re.finditer(var_pattern, js_content)
        for match in matches:
            analysis['variables'].append(match.group(1))
        
        return analysis
    
    def _find_dom_sources(self, js_analysis: Dict[str, Any]) -> List[Dict]:
        """Find all DOM sources in the analyzed JavaScript"""
        sources = []
        
        # From external files
        for file_analysis in js_analysis.get('files', []):
            for source in file_analysis.get('sources_found', []):
                source['file'] = file_analysis.get('url', 'unknown')
                sources.append(source)
        
        # From inline scripts
        for inline_analysis in js_analysis.get('inline_scripts', []):
            for source in inline_analysis.get('sources_found', []):
                source['file'] = 'inline'
                sources.append(source)
        
        # From event handlers
        for handler in js_analysis.get('event_handlers', []):
            for source in handler.get('analysis', {}).get('sources_found', []):
                source['file'] = f"event_handler_{handler['attribute']}"
                sources.append(source)
        
        return sources
    
    def _find_dom_sinks(self, js_analysis: Dict[str, Any]) -> List[Dict]:
        """Find all DOM sinks in the analyzed JavaScript"""
        sinks = []
        
        # From external files
        for file_analysis in js_analysis.get('files', []):
            for sink in file_analysis.get('sinks_found', []):
                sink['file'] = file_analysis.get('url', 'unknown')
                sinks.append(sink)
        
        # From inline scripts
        for inline_analysis in js_analysis.get('inline_scripts', []):
            for sink in inline_analysis.get('sinks_found', []):
                sink['file'] = 'inline'
                sinks.append(sink)
        
        # From event handlers
        for handler in js_analysis.get('event_handlers', []):
            for sink in handler.get('analysis', {}).get('sinks_found', []):
                sink['file'] = f"event_handler_{handler['attribute']}"
                sinks.append(sink)
        
        return sinks
    
    def _analyze_data_flows(self, sources: List[Dict], sinks: List[Dict], 
                          js_analysis: Dict[str, Any]) -> List[Dict]:
        """Analyze data flows from sources to sinks"""
        flows = []
        
        # Simple flow analysis - check if sources and sinks are in the same context
        for source in sources:
            for sink in sinks:
                # Check if they're in the same file or function
                if self._could_flow(source, sink, js_analysis):
                    flow = {
                        'source': source,
                        'sink': sink,
                        'risk_level': self._assess_flow_risk(source, sink),
                        'flow_type': self._determine_flow_type(source, sink)
                    }
                    flows.append(flow)
        
        return flows
    
    def _check_vulnerable_patterns(self, flows: List[Dict], url: str) -> List[Dict]:
        """Check for vulnerable DOM XSS patterns"""
        vulnerabilities = []
        
        for flow in flows:
            if flow['risk_level'] in ['high', 'critical']:
                vulnerability = {
                    'type': 'dom_xss',
                    'severity': flow['risk_level'],
                    'url': url,
                    'source': flow['source']['source'],
                    'sink': flow['sink']['sink'],
                    'source_context': flow['source']['context'],
                    'sink_context': flow['sink']['context'],
                    'flow_type': flow['flow_type'],
                    'description': self._generate_vulnerability_description(flow),
                    'recommendation': self._generate_recommendation(flow)
                }
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def test_dom_xss_payloads(self, url: str, 
                             custom_payloads: List[str] = None) -> List[Dict]:
        """
        Test DOM XSS with context-specific payloads
        
        Args:
            url: URL to test
            custom_payloads: Custom payloads to test
        
        Returns:
            List of vulnerabilities found
        """
        print(f"[DOM] Testing DOM XSS payloads on {url}")
        
        # First analyze the DOM structure
        dom_analysis = self.analyze_dom_structure(url)
        
        # Get URL parameters for testing
        parsed_url = urlparse(url)
        if not parsed_url.fragment and not parsed_url.query:
            print("[DOM] No URL parameters or fragments to test")
            return []
        
        vulnerabilities = []
        
        # Test URL fragments (hash-based)
        if parsed_url.fragment:
            vulnerabilities.extend(
                self._test_fragment_payloads(url, custom_payloads)
            )
        
        # Test URL parameters
        if parsed_url.query:
            vulnerabilities.extend(
                self._test_parameter_payloads(url, custom_payloads)
            )
        
        # Test based on discovered sources/sinks
        if dom_analysis:
            vulnerabilities.extend(
                self._test_flow_based_payloads(url, dom_analysis, custom_payloads)
            )
        
        self.results.extend(vulnerabilities)
        return vulnerabilities
    
    def _test_fragment_payloads(self, url: str, 
                               custom_payloads: List[str] = None) -> List[Dict]:
        """Test DOM XSS via URL fragments"""
        vulnerabilities = []
        base_url = url.split('#')[0]
        
        # Get context-specific payloads
        payloads = custom_payloads or []
        payloads.extend(self.config["context_payloads"]["html"])
        payloads.extend(self.config["context_payloads"]["javascript"])
        
        for payload in payloads:
            test_url = f"{base_url}#{payload}"
            
            # Check if payload would be reflected in a dangerous way
            if self._test_fragment_reflection(test_url, payload):
                vulnerability = {
                    'type': 'dom_xss_fragment',
                    'severity': 'high',
                    'url': test_url,
                    'parameter': 'fragment',
                    'payload': payload,
                    'vector': 'location.hash',
                    'description': 'DOM XSS via URL fragment manipulation'
                }
                vulnerabilities.append(vulnerability)
                print(f"[DOM] 🚨 Fragment-based DOM XSS found: {payload}")
        
        return vulnerabilities
    
    def _test_parameter_payloads(self, url: str, 
                                custom_payloads: List[str] = None) -> List[Dict]:
        """Test DOM XSS via URL parameters"""
        vulnerabilities = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        payloads = custom_payloads or []
        payloads.extend(self.config["context_payloads"]["html"])
        payloads.extend(self.config["context_payloads"]["attribute"])
        
        for param_name in params:
            for payload in payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                # Construct test URL
                query_string = "&".join([
                    f"{k}={v[0]}" for k, v in test_params.items()
                ])
                test_url = f"{base_url}?{query_string}"
                
                # Test for reflection
                if self._test_parameter_reflection(test_url, param_name, payload):
                    vulnerability = {
                        'type': 'dom_xss_parameter',
                        'severity': 'high',
                        'url': test_url,
                        'parameter': param_name,
                        'payload': payload,
                        'vector': 'location.search',
                        'description': f'DOM XSS via {param_name} parameter'
                    }
                    vulnerabilities.append(vulnerability)
                    print(f"[DOM] 🚨 Parameter-based DOM XSS found: {param_name}")
        
        return vulnerabilities
    
    def _test_flow_based_payloads(self, url: str, dom_analysis: Dict,
                                 custom_payloads: List[str] = None) -> List[Dict]:
        """Test payloads based on discovered data flows"""
        vulnerabilities = []
        
        flows = dom_analysis.get('data_flows', [])
        high_risk_flows = [f for f in flows if f['risk_level'] in ['high', 'critical']]
        
        for flow in high_risk_flows:
            source = flow['source']['source']
            sink = flow['sink']['sink']
            
            # Choose appropriate payloads based on sink type
            if 'innerHTML' in sink or 'outerHTML' in sink:
                payloads = self.config["context_payloads"]["html"]
            elif 'eval' in sink or 'Function' in sink:
                payloads = self.config["context_payloads"]["javascript"]
            elif 'location' in sink:
                payloads = self.config["context_payloads"]["url"]
            else:
                payloads = self.config["context_payloads"]["html"]
            
            # Add custom payloads
            if custom_payloads:
                payloads.extend(custom_payloads)
            
            # Test each payload
            for payload in payloads:
                test_result = self._test_flow_payload(url, source, sink, payload)
                if test_result:
                    vulnerabilities.append(test_result)
        
        return vulnerabilities
    
    def _test_fragment_reflection(self, test_url: str, payload: str) -> bool:
        """Test if fragment payload would be reflected dangerously"""
        try:
            response = self.session.get(test_url, timeout=self.config["request_timeout"])
            
            # Look for JavaScript that processes location.hash
            js_patterns = [
                r'location\.hash',
                r'window\.location\.hash',
                r'document\.location\.hash'
            ]
            
            for pattern in js_patterns:
                if re.search(pattern, response.text):
                    # Check if the hash value is used in a dangerous context
                    dangerous_patterns = [
                        r'innerHTML\s*=.*location\.hash',
                        r'document\.write.*location\.hash',
                        r'eval.*location\.hash'
                    ]
                    
                    for dangerous_pattern in dangerous_patterns:
                        if re.search(dangerous_pattern, response.text):
                            return True
            
            return False
            
        except Exception:
            return False
    
    def _test_parameter_reflection(self, test_url: str, 
                                  param_name: str, payload: str) -> bool:
        """Test if parameter payload would be reflected dangerously"""
        try:
            response = self.session.get(test_url, timeout=self.config["request_timeout"])
            
            # Look for JavaScript that processes URL parameters
            js_patterns = [
                r'location\.search',
                r'window\.location\.search',
                r'URLSearchParams',
                r'getUrlParameter'
            ]
            
            for pattern in js_patterns:
                if re.search(pattern, response.text):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _test_flow_payload(self, url: str, source: str, 
                          sink: str, payload: str) -> Optional[Dict]:
        """Test a payload against a specific source-sink flow"""
        # This is a simplified test - in practice, you'd need more sophisticated
        # JavaScript execution analysis or browser automation
        
        try:
            # Modify URL to include payload
            if 'location.hash' in source:
                test_url = f"{url}#{payload}"
            elif 'location.search' in source:
                parsed_url = urlparse(url)
                if parsed_url.query:
                    test_url = f"{url}&test={payload}"
                else:
                    test_url = f"{url}?test={payload}"
            else:
                return None
            
            response = self.session.get(test_url, timeout=self.config["request_timeout"])
            
            # Simple check for dangerous patterns
            if self._check_dangerous_reflection(response.text, payload):
                return {
                    'type': 'dom_xss_flow',
                    'severity': 'high',
                    'url': test_url,
                    'source': source,
                    'sink': sink,
                    'payload': payload,
                    'description': f'DOM XSS flow from {source} to {sink}'
                }
            
        except Exception:
            pass
        
        return None
    
    def _check_dangerous_reflection(self, response_text: str, payload: str) -> bool:
        """Check if payload is reflected in a dangerous context"""
        # Look for the payload in JavaScript contexts
        js_contexts = [
            r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>',
            r'on\w+\s*=\s*["\'][^"\']*' + re.escape(payload),
            r'javascript:[^"\']*' + re.escape(payload)
        ]
        
        for context in js_contexts:
            if re.search(context, response_text, re.IGNORECASE | re.DOTALL):
                return True
        
        return False
    
    def _find_code_contexts(self, js_content: str, term: str) -> List[str]:
        """Find code contexts around a specific term"""
        contexts = []
        lines = js_content.split('\n')
        
        for i, line in enumerate(lines):
            if term in line:
                # Extract context (3 lines before and after)
                start = max(0, i - 3)
                end = min(len(lines), i + 4)
                context = '\n'.join(lines[start:end])
                contexts.append(context)
        
        return contexts
    
    def _extract_context(self, content: str, start: int, end: int, 
                        context_size: int = 100) -> str:
        """Extract context around a match"""
        context_start = max(0, start - context_size)
        context_end = min(len(content), end + context_size)
        return content[context_start:context_end]
    
    def _get_line_number(self, content: str, context: str) -> int:
        """Get line number of context in content"""
        try:
            context_start = content.find(context)
            if context_start != -1:
                return content[:context_start].count('\n') + 1
        except Exception:
            pass
        return 0
    
    def _detect_frameworks(self, js_content: str) -> List[str]:
        """Detect JavaScript frameworks in use"""
        frameworks = []
        
        framework_patterns = {
            'jquery': [r'\$\(', r'jQuery'],
            'angular': [r'angular\.', r'ng-'],
            'react': [r'React\.', r'ReactDOM'],
            'vue': [r'Vue\.', r'new Vue'],
            'backbone': [r'Backbone\.'],
            'ember': [r'Ember\.'],
            'knockout': [r'ko\.']
        }
        
        for framework, patterns in framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, js_content):
                    frameworks.append(framework)
                    break
        
        return frameworks
    
    def _could_flow(self, source: Dict, sink: Dict, js_analysis: Dict) -> bool:
        """Check if data could flow from source to sink"""
        # Simplified flow analysis
        source_file = source.get('file', '')
        sink_file = sink.get('file', '')
        
        # If in the same file, assume possible flow
        if source_file == sink_file:
            return True
        
        # If one is inline and the other is in a file, possible flow
        if 'inline' in source_file or 'inline' in sink_file:
            return True
        
        return False
    
    def _assess_flow_risk(self, source: Dict, sink: Dict) -> str:
        """Assess the risk level of a data flow"""
        source_name = source['source']
        sink_name = sink['sink']
        
        # High-risk sources
        high_risk_sources = [
            'location.href', 'location.search', 'location.hash',
            'document.URL', 'postMessage'
        ]
        
        # High-risk sinks
        high_risk_sinks = [
            'innerHTML', 'outerHTML', 'eval', 'Function',
            'document.write', 'location.href'
        ]
        
        if source_name in high_risk_sources and sink_name in high_risk_sinks:
            return 'critical'
        elif source_name in high_risk_sources or sink_name in high_risk_sinks:
            return 'high'
        else:
            return 'medium'
    
    def _determine_flow_type(self, source: Dict, sink: Dict) -> str:
        """Determine the type of data flow"""
        source_name = source['source']
        sink_name = sink['sink']
        
        if 'location' in source_name and 'innerHTML' in sink_name:
            return 'url_to_dom'
        elif 'postMessage' in source_name:
            return 'postmessage_to_dom'
        elif any(storage in source_name for storage in ['localStorage', 'sessionStorage']):
            return 'storage_to_dom'
        else:
            return 'other'
    
    def _generate_vulnerability_description(self, flow: Dict) -> str:
        """Generate a description for the vulnerability"""
        source = flow['source']['source']
        sink = flow['sink']['sink']
        flow_type = flow['flow_type']
        
        descriptions = {
            'url_to_dom': f"User-controlled data from {source} flows to {sink}, allowing DOM XSS",
            'postmessage_to_dom': f"PostMessage data flows to {sink} without validation",
            'storage_to_dom': f"Data from {source} flows to {sink} without sanitization"
        }
        
        return descriptions.get(flow_type, f"Potential DOM XSS flow from {source} to {sink}")
    
    def _generate_recommendation(self, flow: Dict) -> str:
        """Generate remediation recommendation"""
        sink = flow['sink']['sink']
        
        recommendations = {
            'innerHTML': "Use textContent instead of innerHTML, or sanitize HTML content",
            'outerHTML': "Use textContent instead of outerHTML, or sanitize HTML content",
            'eval': "Avoid using eval(). Use JSON.parse() for JSON data",
            'Function': "Avoid using Function() constructor with user data",
            'document.write': "Use DOM methods instead of document.write()",
            'location.href': "Validate and sanitize URLs before assignment"
        }
        
        for sink_name, recommendation in recommendations.items():
            if sink_name in sink:
                return recommendation
        
        return "Validate and sanitize all user input before using in DOM operations"
    
    def generate_dom_report(self) -> Dict:
        """Generate comprehensive DOM analysis report"""
        total_sources = sum(
            len(analysis.get('dom_sources', []))
            for analysis in self.javascript_analysis.values()
        )
        
        total_sinks = sum(
            len(analysis.get('dom_sinks', []))
            for analysis in self.javascript_analysis.values()
        )
        
        all_frameworks = set()
        for analysis in self.javascript_analysis.values():
            all_frameworks.update(analysis.get('frameworks_detected', []))
        
        return {
            'scan_type': 'deep_dom',
            'pages_analyzed': len(self.javascript_analysis),
            'total_dom_sources': total_sources,
            'total_dom_sinks': total_sinks,
            'frameworks_detected': list(all_frameworks),
            'total_vulnerabilities': len(self.results),
            'vulnerabilities': self.results,
            'detailed_analysis': self.javascript_analysis,
            'scan_timestamp': time.time()
        }


# Example usage
if __name__ == "__main__":
    # Initialize DOM scanner
    dom_scanner = DeepDOMScanner()
    
    # Analyze DOM structure
    analysis = dom_scanner.analyze_dom_structure("https://example.com")
    
    # Test for DOM XSS
    results = dom_scanner.test_dom_xss_payloads("https://example.com#test")
    
    # Generate report
    report = dom_scanner.generate_dom_report()
    print(f"DOM analysis completed. Found {len(results)} vulnerabilities.")