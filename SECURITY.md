# Security Policy

## Supported Versions

We actively support the following versions of XSSProbe with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.9.x   | :white_check_mark: |
| 1.8.x   | :x:                |
| < 1.8   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in XSSProbe, please follow these steps:

### 🔒 Private Reporting

**Please do NOT create a public GitHub issue for security vulnerabilities.**

Instead, please report security issues privately to:
- **Email**: ppr0gr4m3rr@gmail.com
- **Subject**: [SECURITY] XSSProbe Vulnerability Report

### 📝 What to Include

When reporting a vulnerability, please include:

1. **Description**: A clear description of the vulnerability
2. **Steps to Reproduce**: Detailed steps to reproduce the issue
3. **Impact**: Potential impact and severity assessment
4. **Proof of Concept**: If possible, include a PoC (without causing harm)
5. **Suggested Fix**: If you have ideas for fixing the issue
6. **Your Contact Info**: So we can follow up with questions

### ⏱️ Response Timeline

- **Initial Response**: Within 48 hours
- **Triage**: Within 1 week  
- **Fix Development**: 2-4 weeks (depending on complexity)
- **Public Disclosure**: After fix is released and deployed

### 🎯 Security Best Practices

When using XSSProbe:

#### ✅ Do:
- Only test applications you own or have explicit permission to test
- Use in controlled, isolated environments
- Follow responsible disclosure practices
- Keep the tool updated to the latest version
- Review and understand the code before running

#### ❌ Don't:
- Test third-party applications without authorization
- Use for malicious purposes
- Run against production systems without proper approval
- Share or distribute unauthorized scan results
- Ignore rate limiting or other protective measures

### 🔐 Secure Development

For contributors:

- **Input Validation**: Always validate and sanitize user inputs
- **Error Handling**: Avoid exposing sensitive information in error messages
- **Dependencies**: Keep dependencies updated and scan for vulnerabilities
- **Code Review**: All security-related changes require thorough review
- **Testing**: Include security test cases for new features

### 🏆 Recognition

We believe in recognizing security researchers who help make XSSProbe more secure:

- **Public Credit**: With your permission, we'll credit you in our security advisories
- **Hall of Fame**: Contributors will be listed in our security hall of fame
- **Collaboration**: Opportunity to collaborate on fixes and improvements

### 📚 Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Responsible Disclosure Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)
- [CVE Database](https://cve.mitre.org/)

### 🤝 Security Community

Join our security-focused discussions:
- **Security Issues**: [GitHub Security Tab](https://github.com/adityanageshsir/XSSProbe/security)
- **Community Discord**: [Hacktoberfest Discord](https://discord.gg/hacktoberfest)

---

**Note**: This security policy applies to the XSSProbe project itself. For security issues in target applications discovered using XSSProbe, please follow responsible disclosure practices and report directly to the affected organizations.

Thank you for helping keep XSSProbe and the broader security community safe! 🛡️