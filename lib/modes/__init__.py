"""
Advanced Scanning Modes for XSSProbe
Provides stealth, authenticated, and specialized scanning capabilities
"""

from .stealth_scanner import StealthScanner
from .authenticated_scanner import AuthenticatedScanner
from .blind_xss_scanner import BlindXSSScanner
from .api_scanner import APIScanner
from .deep_dom_scanner import DeepDOMScanner

__all__ = [
    'StealthScanner',
    'AuthenticatedScanner', 
    'BlindXSSScanner',
    'APIScanner',
    'DeepDOMScanner'
]

# Version info
__version__ = "1.0.0"
__author__ = "XSSProbe Team"
__description__ = "Advanced scanning modes for comprehensive XSS detection"