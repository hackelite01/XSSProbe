"""
Configuration settings for XSSProbe
"""
from typing import Dict, List

class Config:
    """Configuration class for XSSProbe settings"""
    
    # Default values
    DEFAULT_TIMEOUT: int = 10
    DEFAULT_DEPTH: int = 2
    DEFAULT_METHOD: int = 2  # 0=GET, 1=POST, 2=BOTH
    DEFAULT_PAYLOAD_LEVEL: int = 6
    MAX_THREADS: int = 5
    
    # File settings
    OUTPUT_FILE: str = "xss_results.txt"
    DOM_XSS_OUTPUT: str = "dom_xss_results.txt"
    LOG_FILE: str = "xssprobe.log"
    
    # HTTP settings
    DEFAULT_USER_AGENT: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    DEFAULT_HEADERS: Dict[str, str] = {
        'User-Agent': DEFAULT_USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    
    # SSL/TLS settings
    VERIFY_SSL: bool = False  # Set to True for production use
    
    # Rate limiting
    REQUESTS_PER_SECOND: float = 1.0
    
    # Payload settings
    PAYLOAD_FUNCTIONS: List[str] = [
        "prompt(5000/200)",
        "alert(6000/3000)", 
        "alert(document.cookie)",
        "prompt(document.cookie)",
        "console.log(5000/3000)"
    ]
    
    # Crawler settings
    MAX_URLS_PER_DEPTH: int = 100
    EXCLUDED_EXTENSIONS: List[str] = [
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.tar', '.gz', '.7z',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv',
        '.css', '.js', '.ico'
    ]
    
    # DOM XSS specific settings
    DOM_XSS_TIMEOUT: int = 15
    DOM_XSS_MAX_PAYLOADS: int = 20

    @classmethod
    def get_default_cookie(cls) -> str:
        """Get default cookie configuration"""
        return '{"session": "xssprobe_test"}'
    
    @classmethod  
    def validate_url(cls, url: str) -> bool:
        """Validate if URL is properly formatted"""
        from urllib.parse import urlparse
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @classmethod
    def get_safe_filename(cls, url: str) -> str:
        """Generate safe filename from URL"""
        import re
        safe_name = re.sub(r'[^\w\-_.]', '_', url)
        return safe_name[:100] + '.txt'  # Limit length