"""
API Scanner Mode for XSSProbe
Specialized scanner for REST APIs, GraphQL, and other API endpoints
"""

import requests
import json
import time
import re
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urljoin, urlparse, parse_qs
import xml.etree.ElementTree as ET
import yaml
from dataclasses import dataclass


@dataclass
class APIEndpoint:
    """Represents an API endpoint"""
    url: str
    method: str
    parameters: Dict[str, Any]
    headers: Dict[str, str]
    endpoint_type: str  # rest, graphql, soap, etc.
    auth_required: bool = False


class APIScanner:
    """
    Scanner specialized for API endpoints and web services
    """
    
    def __init__(self, session: requests.Session = None, config: Dict[str, Any] = None):
        self.session = session or requests.Session()
        self.config = config or self._get_default_config()
        self.discovered_endpoints = []
        self.results = []
        self.api_schemas = {}
        
    def _get_default_config(self) -> Dict[str, Any]:
        """Default API scanner configuration"""
        return {
            "common_api_paths": [
                "/api", "/v1", "/v2", "/v3", "/rest", "/graphql",
                "/api/v1", "/api/v2", "/api/v3", "/services",
                "/webservice", "/ws", "/rpc", "/json-rpc"
            ],
            "common_api_extensions": [
                ".json", ".xml", ".yaml", ".yml"
            ],
            "api_discovery_wordlist": [
                "users", "user", "admin", "auth", "login", "register",
                "profile", "account", "settings", "config", "status",
                "health", "info", "version", "docs", "swagger",
                "openapi", "schema", "metadata", "search", "query"
            ],
            "http_methods": [
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"
            ],
            "content_types": [
                "application/json",
                "application/xml",
                "text/xml",
                "application/x-www-form-urlencoded",
                "multipart/form-data",
                "text/plain",
                "application/graphql"
            ],
            "max_depth": 3,
            "request_timeout": 15,
            "rate_limit_delay": 0.5,
            "include_swagger": True,
            "include_graphql": True,
            "include_soap": True
        }
    
    def discover_api_endpoints(self, base_url: str) -> List[APIEndpoint]:
        """
        Discover API endpoints from a base URL
        
        Args:
            base_url: Base URL to scan for APIs
        
        Returns:
            List of discovered API endpoints
        """
        print(f"[API] Discovering API endpoints from {base_url}")
        
        endpoints = []
        
        # Try common API paths
        endpoints.extend(self._discover_common_paths(base_url))
        
        # Look for API documentation
        endpoints.extend(self._discover_from_docs(base_url))
        
        # Try directory traversal
        endpoints.extend(self._discover_by_crawling(base_url))
        
        # Look for GraphQL endpoints
        if self.config["include_graphql"]:
            endpoints.extend(self._discover_graphql_endpoints(base_url))
        
        # Look for SOAP endpoints
        if self.config["include_soap"]:
            endpoints.extend(self._discover_soap_endpoints(base_url))
        
        self.discovered_endpoints = endpoints
        print(f"[API] Discovered {len(endpoints)} API endpoints")
        
        return endpoints
    
    def _discover_common_paths(self, base_url: str) -> List[APIEndpoint]:
        """Discover APIs using common paths"""
        endpoints = []
        
        for path in self.config["common_api_paths"]:
            for endpoint in self.config["api_discovery_wordlist"]:
                test_url = urljoin(base_url, f"{path}/{endpoint}")
                
                for method in ["GET", "POST"]:
                    try:
                        time.sleep(self.config["rate_limit_delay"])
                        
                        if method == "GET":
                            response = self.session.get(
                                test_url, 
                                timeout=self.config["request_timeout"]
                            )
                        else:
                            response = self.session.post(
                                test_url,
                                json={},
                                timeout=self.config["request_timeout"]
                            )
                        
                        if self._is_api_response(response):
                            endpoint_obj = APIEndpoint(
                                url=test_url,
                                method=method,
                                parameters=self._extract_parameters(response),
                                headers=dict(response.headers),
                                endpoint_type="rest"
                            )
                            endpoints.append(endpoint_obj)
                            print(f"[API] Found REST endpoint: {method} {test_url}")
                    
                    except requests.RequestException:
                        continue
        
        return endpoints
    
    def _discover_from_docs(self, base_url: str) -> List[APIEndpoint]:
        """Discover APIs from documentation"""
        endpoints = []
        
        # Common documentation paths
        doc_paths = [
            "/swagger.json", "/swagger.yaml", "/swagger-ui",
            "/openapi.json", "/openapi.yaml", "/api-docs",
            "/docs", "/documentation", "/api/docs",
            "/redoc", "/rapidoc"
        ]
        
        for path in doc_paths:
            try:
                doc_url = urljoin(base_url, path)
                response = self.session.get(
                    doc_url, 
                    timeout=self.config["request_timeout"]
                )
                
                if response.status_code == 200:
                    # Parse Swagger/OpenAPI documentation
                    if any(keyword in path for keyword in ["swagger", "openapi"]):
                        endpoints.extend(self._parse_openapi_spec(response, base_url))
                    
                    print(f"[API] Found API documentation at {doc_url}")
            
            except requests.RequestException:
                continue
        
        return endpoints
    
    def _discover_by_crawling(self, base_url: str) -> List[APIEndpoint]:
        """Discover APIs by crawling"""
        endpoints = []
        visited = set()
        to_visit = [base_url]
        depth = 0
        
        while to_visit and depth < self.config["max_depth"]:
            current_urls = to_visit[:]
            to_visit = []
            depth += 1
            
            for url in current_urls:
                if url in visited:
                    continue
                
                visited.add(url)
                
                try:
                    response = self.session.get(
                        url, 
                        timeout=self.config["request_timeout"]
                    )
                    
                    # Check if this is an API endpoint
                    if self._is_api_response(response):
                        endpoint_obj = APIEndpoint(
                            url=url,
                            method="GET",
                            parameters=self._extract_parameters(response),
                            headers=dict(response.headers),
                            endpoint_type=self._detect_api_type(response)
                        )
                        endpoints.append(endpoint_obj)
                    
                    # Extract links for further crawling
                    if depth < self.config["max_depth"]:
                        links = self._extract_api_links(response.text, url)
                        to_visit.extend(links)
                
                except requests.RequestException:
                    continue
                
                time.sleep(self.config["rate_limit_delay"])
        
        return endpoints
    
    def _discover_graphql_endpoints(self, base_url: str) -> List[APIEndpoint]:
        """Discover GraphQL endpoints"""
        endpoints = []
        
        graphql_paths = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql"]
        
        for path in graphql_paths:
            try:
                graphql_url = urljoin(base_url, path)
                
                # Test with introspection query
                introspection_query = {
                    "query": "query IntrospectionQuery { __schema { queryType { name } } }"
                }
                
                response = self.session.post(
                    graphql_url,
                    json=introspection_query,
                    headers={"Content-Type": "application/json"},
                    timeout=self.config["request_timeout"]
                )
                
                if response.status_code == 200:
                    try:
                        result = response.json()
                        if "data" in result or "errors" in result:
                            endpoint_obj = APIEndpoint(
                                url=graphql_url,
                                method="POST",
                                parameters={"query": "string", "variables": "object"},
                                headers={"Content-Type": "application/json"},
                                endpoint_type="graphql"
                            )
                            endpoints.append(endpoint_obj)
                            print(f"[API] Found GraphQL endpoint: {graphql_url}")
                    except json.JSONDecodeError:
                        pass
            
            except requests.RequestException:
                continue
        
        return endpoints
    
    def _discover_soap_endpoints(self, base_url: str) -> List[APIEndpoint]:
        """Discover SOAP endpoints"""
        endpoints = []
        
        soap_paths = ["/soap", "/webservice", "/ws", "/services"]
        
        for path in soap_paths:
            try:
                soap_url = urljoin(base_url, path)
                
                # Try to get WSDL
                wsdl_url = f"{soap_url}?wsdl"
                response = self.session.get(
                    wsdl_url, 
                    timeout=self.config["request_timeout"]
                )
                
                if (response.status_code == 200 and 
                    "wsdl" in response.text.lower()):
                    
                    endpoint_obj = APIEndpoint(
                        url=soap_url,
                        method="POST",
                        parameters=self._parse_wsdl_parameters(response.text),
                        headers={"Content-Type": "text/xml", "SOAPAction": ""},
                        endpoint_type="soap"
                    )
                    endpoints.append(endpoint_obj)
                    print(f"[API] Found SOAP endpoint: {soap_url}")
            
            except requests.RequestException:
                continue
        
        return endpoints
    
    def scan_api_endpoints(self, endpoints: List[APIEndpoint] = None,
                          payloads: List[str] = None) -> List[Dict]:
        """
        Scan API endpoints for XSS vulnerabilities
        
        Args:
            endpoints: List of API endpoints to scan
            payloads: XSS payloads to test
        
        Returns:
            List of vulnerabilities found
        """
        if not endpoints:
            endpoints = self.discovered_endpoints
        
        if not payloads:
            payloads = self._get_api_payloads()
        
        print(f"[API] Scanning {len(endpoints)} API endpoints")
        
        for endpoint in endpoints:
            self._scan_single_endpoint(endpoint, payloads)
        
        print(f"[API] ✅ Scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    def _scan_single_endpoint(self, endpoint: APIEndpoint, payloads: List[str]):
        """Scan a single API endpoint"""
        print(f"[API] Testing {endpoint.method} {endpoint.url}")
        
        if endpoint.endpoint_type == "graphql":
            self._scan_graphql_endpoint(endpoint, payloads)
        elif endpoint.endpoint_type == "soap":
            self._scan_soap_endpoint(endpoint, payloads)
        else:
            self._scan_rest_endpoint(endpoint, payloads)
    
    def _scan_rest_endpoint(self, endpoint: APIEndpoint, payloads: List[str]):
        """Scan REST API endpoint"""
        for payload in payloads:
            # Test in URL parameters
            if endpoint.method == "GET":
                for param_name in endpoint.parameters:
                    test_params = endpoint.parameters.copy()
                    test_params[param_name] = payload
                    
                    vulnerability = self._test_api_payload(
                        endpoint.url, "GET", params=test_params,
                        param_name=param_name, payload=payload,
                        endpoint_type="rest"
                    )
                    
                    if vulnerability:
                        self.results.append(vulnerability)
            
            # Test in JSON body
            elif endpoint.method in ["POST", "PUT", "PATCH"]:
                # Test each parameter in JSON body
                for param_name in endpoint.parameters:
                    json_data = {param_name: payload}
                    
                    vulnerability = self._test_api_payload(
                        endpoint.url, endpoint.method, json=json_data,
                        param_name=param_name, payload=payload,
                        endpoint_type="rest"
                    )
                    
                    if vulnerability:
                        self.results.append(vulnerability)
                
                # Test in form data
                form_data = {list(endpoint.parameters.keys())[0]: payload}
                vulnerability = self._test_api_payload(
                    endpoint.url, endpoint.method, data=form_data,
                    param_name=list(endpoint.parameters.keys())[0],
                    payload=payload, endpoint_type="rest"
                )
                
                if vulnerability:
                    self.results.append(vulnerability)
            
            # Test in headers
            for header_name in ["X-Custom-Header", "User-Agent", "Referer"]:
                test_headers = endpoint.headers.copy()
                test_headers[header_name] = payload
                
                vulnerability = self._test_api_payload(
                    endpoint.url, endpoint.method, headers=test_headers,
                    param_name=header_name, payload=payload,
                    endpoint_type="rest"
                )
                
                if vulnerability:
                    self.results.append(vulnerability)
    
    def _scan_graphql_endpoint(self, endpoint: APIEndpoint, payloads: List[str]):
        """Scan GraphQL endpoint"""
        for payload in payloads:
            # Test in query variables
            test_query = {
                "query": "query TestQuery($input: String) { test(input: $input) }",
                "variables": {"input": payload}
            }
            
            vulnerability = self._test_api_payload(
                endpoint.url, "POST", json=test_query,
                param_name="variables.input", payload=payload,
                endpoint_type="graphql"
            )
            
            if vulnerability:
                self.results.append(vulnerability)
            
            # Test in query string itself
            malicious_query = {
                "query": f"query {{ test(input: \"{payload}\") }}"
            }
            
            vulnerability = self._test_api_payload(
                endpoint.url, "POST", json=malicious_query,
                param_name="query", payload=payload,
                endpoint_type="graphql"
            )
            
            if vulnerability:
                self.results.append(vulnerability)
    
    def _scan_soap_endpoint(self, endpoint: APIEndpoint, payloads: List[str]):
        """Scan SOAP endpoint"""
        for payload in payloads:
            # Create SOAP envelope with payload
            soap_envelope = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <TestMethod>
            <parameter>{payload}</parameter>
        </TestMethod>
    </soap:Body>
</soap:Envelope>"""
            
            headers = endpoint.headers.copy()
            headers["Content-Type"] = "text/xml"
            
            vulnerability = self._test_api_payload(
                endpoint.url, "POST", data=soap_envelope,
                headers=headers, param_name="soap_parameter",
                payload=payload, endpoint_type="soap"
            )
            
            if vulnerability:
                self.results.append(vulnerability)
    
    def _test_api_payload(self, url: str, method: str, 
                         param_name: str, payload: str,
                         endpoint_type: str, **kwargs) -> Optional[Dict]:
        """Test a single payload against an API endpoint"""
        try:
            # Make request
            if method == "GET":
                response = self.session.get(
                    url, 
                    timeout=self.config["request_timeout"],
                    **kwargs
                )
            elif method == "POST":
                response = self.session.post(
                    url, 
                    timeout=self.config["request_timeout"],
                    **kwargs
                )
            elif method == "PUT":
                response = self.session.put(
                    url, 
                    timeout=self.config["request_timeout"],
                    **kwargs
                )
            elif method == "PATCH":
                response = self.session.patch(
                    url, 
                    timeout=self.config["request_timeout"],
                    **kwargs
                )
            else:
                return None
            
            # Check for XSS indicators
            if self._check_api_xss_indicators(response, payload):
                return {
                    'type': 'api_xss',
                    'severity': 'high',
                    'url': url,
                    'method': method,
                    'parameter': param_name,
                    'payload': payload,
                    'endpoint_type': endpoint_type,
                    'response_snippet': self._truncate_response(response.text),
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', '')
                }
        
        except requests.RequestException as e:
            print(f"[API] Error testing payload: {e}")
        
        return None
    
    def _check_api_xss_indicators(self, response: requests.Response, 
                                 payload: str) -> bool:
        """Check API response for XSS indicators"""
        response_text = response.text
        
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
        
        # Check JSON response for payload
        try:
            json_response = response.json()
            json_str = json.dumps(json_response)
            
            if payload in json_str or any(variant in json_str for variant in decoded_variants):
                return True
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Check XML response
        if 'xml' in response.headers.get('Content-Type', '').lower():
            try:
                root = ET.fromstring(response_text)
                xml_str = ET.tostring(root, encoding='unicode')
                
                if payload in xml_str or any(variant in xml_str for variant in decoded_variants):
                    return True
            except ET.ParseError:
                pass
        
        return False
    
    def _get_api_payloads(self) -> List[str]:
        """Get API-specific XSS payloads"""
        return [
            # JSON context payloads
            '"},{"xss":"<script>alert(1)</script>',
            '"}],"xss":"<script>alert(1)</script>"',
            '<script>alert("XSS")</script>',
            
            # XML context payloads
            '</item><script>alert(1)</script><item>',
            ']]></value><script>alert(1)</script><value><![CDATA[',
            
            # Header injection payloads
            '\r\nX-XSS: <script>alert(1)</script>',
            
            # GraphQL specific
            '\\n\\r\\n<script>alert(1)</script>',
            
            # URL encoded variants
            '%3Cscript%3Ealert(1)%3C/script%3E',
            
            # Unicode variants
            '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
            
            # Basic payloads
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            'javascript:alert(1)',
            
            # Polyglot payloads for APIs
            '";alert(1);//',
            "'><script>alert(1)</script>",
            '"><script>alert(String.fromCharCode(88,83,83))</script>'
        ]
    
    def _is_api_response(self, response: requests.Response) -> bool:
        """Check if response is from an API"""
        content_type = response.headers.get('Content-Type', '').lower()
        
        # Check content type
        api_content_types = [
            'application/json', 'application/xml', 'text/xml',
            'application/graphql', 'text/plain'
        ]
        
        if any(ct in content_type for ct in api_content_types):
            return True
        
        # Check response content
        try:
            # Try to parse as JSON
            response.json()
            return True
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Check for XML
        if response.text.strip().startswith('<?xml') or response.text.strip().startswith('<'):
            return True
        
        # Check for API-like headers
        api_headers = ['api-version', 'x-api-key', 'x-ratelimit']
        for header in response.headers:
            if any(api_header in header.lower() for api_header in api_headers):
                return True
        
        return False
    
    def _detect_api_type(self, response: requests.Response) -> str:
        """Detect the type of API"""
        content_type = response.headers.get('Content-Type', '').lower()
        
        if 'json' in content_type:
            return 'rest'
        elif 'xml' in content_type:
            if 'soap' in response.text.lower():
                return 'soap'
            return 'rest'
        elif 'graphql' in content_type:
            return 'graphql'
        
        return 'unknown'
    
    def _extract_parameters(self, response: requests.Response) -> Dict[str, str]:
        """Extract potential parameters from API response"""
        parameters = {}
        
        try:
            # Try JSON response
            json_data = response.json()
            parameters.update(self._extract_json_keys(json_data))
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Extract from URL
        parsed_url = urlparse(response.url)
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            for key, values in query_params.items():
                parameters[key] = values[0] if values else ''
        
        return parameters
    
    def _extract_json_keys(self, data: Union[Dict, List], prefix: str = '') -> Dict[str, str]:
        """Recursively extract keys from JSON data"""
        keys = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                
                if isinstance(value, (dict, list)):
                    keys.update(self._extract_json_keys(value, full_key))
                else:
                    keys[full_key] = str(value) if value is not None else ''
        
        elif isinstance(data, list) and data:
            # Take first item as example
            keys.update(self._extract_json_keys(data[0], prefix))
        
        return keys
    
    def _parse_openapi_spec(self, response: requests.Response, 
                           base_url: str) -> List[APIEndpoint]:
        """Parse OpenAPI/Swagger specification"""
        endpoints = []
        
        try:
            if response.headers.get('Content-Type', '').startswith('application/json'):
                spec = response.json()
            else:
                spec = yaml.safe_load(response.text)
            
            # Extract base path
            base_path = spec.get('basePath', '')
            server_url = base_url
            
            # Handle OpenAPI 3.0 servers
            if 'servers' in spec:
                server_url = spec['servers'][0].get('url', base_url)
            
            # Parse paths
            paths = spec.get('paths', {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.upper() in self.config["http_methods"]:
                        full_url = urljoin(server_url, base_path + path)
                        
                        # Extract parameters
                        parameters = {}
                        if 'parameters' in details:
                            for param in details['parameters']:
                                param_name = param.get('name', '')
                                param_type = param.get('type', 'string')
                                parameters[param_name] = param_type
                        
                        endpoint = APIEndpoint(
                            url=full_url,
                            method=method.upper(),
                            parameters=parameters,
                            headers={},
                            endpoint_type="rest"
                        )
                        endpoints.append(endpoint)
        
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            print(f"[API] Error parsing API spec: {e}")
        
        return endpoints
    
    def _parse_wsdl_parameters(self, wsdl_content: str) -> Dict[str, str]:
        """Parse parameters from WSDL"""
        parameters = {}
        
        try:
            # Basic WSDL parsing - extract element names
            import re
            element_pattern = r'<xs:element name="([^"]+)"'
            matches = re.findall(element_pattern, wsdl_content)
            
            for match in matches:
                parameters[match] = 'string'
        
        except Exception as e:
            print(f"[API] Error parsing WSDL: {e}")
        
        return parameters
    
    def _extract_api_links(self, html_content: str, base_url: str) -> List[str]:
        """Extract API-related links from HTML content"""
        links = []
        
        # Look for links that might be API endpoints
        import re
        
        # Find URLs that look like APIs
        api_pattern = r'href=["\']([^"\']*(?:api|rest|graphql|soap)[^"\']*)["\']'
        matches = re.findall(api_pattern, html_content, re.IGNORECASE)
        
        for match in matches:
            full_url = urljoin(base_url, match)
            links.append(full_url)
        
        return links
    
    def _truncate_response(self, response_text: str, max_length: int = 500) -> str:
        """Truncate response text for reporting"""
        if len(response_text) <= max_length:
            return response_text
        
        return response_text[:max_length] + "..."
    
    def generate_api_report(self) -> Dict:
        """Generate comprehensive API scan report"""
        return {
            'scan_type': 'api',
            'total_endpoints_discovered': len(self.discovered_endpoints),
            'endpoints_by_type': self._categorize_endpoints(),
            'total_vulnerabilities': len(self.results),
            'vulnerabilities': self.results,
            'api_technologies_detected': self._detect_api_technologies(),
            'scan_timestamp': time.time()
        }
    
    def _categorize_endpoints(self) -> Dict[str, int]:
        """Categorize discovered endpoints by type"""
        categories = {}
        
        for endpoint in self.discovered_endpoints:
            endpoint_type = endpoint.endpoint_type
            categories[endpoint_type] = categories.get(endpoint_type, 0) + 1
        
        return categories
    
    def _detect_api_technologies(self) -> List[str]:
        """Detect API technologies in use"""
        technologies = set()
        
        for endpoint in self.discovered_endpoints:
            technologies.add(endpoint.endpoint_type)
        
        return list(technologies)


# Example usage
if __name__ == "__main__":
    # Initialize API scanner
    api_scanner = APIScanner()
    
    # Discover API endpoints
    endpoints = api_scanner.discover_api_endpoints("https://api.example.com")
    
    # Scan discovered endpoints
    results = api_scanner.scan_api_endpoints(endpoints)
    
    # Generate report
    report = api_scanner.generate_api_report()
    print(f"API scan completed. Found {len(results)} vulnerabilities across {len(endpoints)} endpoints.")