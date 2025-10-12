import random
import urllib.parse
import html

class PayloadEncoder:
    def __init__(self, config=None):
        self.config = config or {"obfuscation_level": 2}
    
    def encode_payload(self, payload, context="html"):
        if not payload:
            return []
        
        variants = [payload]
        variants.append(urllib.parse.quote(payload))
        variants.append(html.escape(payload))
        
        return variants[:self.config.get("obfuscation_level", 2) * 2]
    
    def generate_evasion_payloads(self, payload, waf_type):
        variants = []
        if waf_type == "cloudflare":
            variants.append(payload.replace('script', 'ScRiPt'))
        variants.append(payload.replace('<script>', '<script/**/'))
        return variants
    
    def get_encoding_statistics(self, payloads):
        if not payloads:
            return {}
        return {"total_payloads": len(payloads)}
