# Contributing to XSSProbe

Thank you for your interest in contributing to XSSProbe! 🎉 We welcome contributions from developers of all skill levels.

## 🎯 Hacktoberfest 2025

This repository participates in [Hacktoberfest](https://hacktoberfest.com/)! We encourage quality contributions during October and throughout the year.

## 📋 Table of Contents

- [Getting Started](#getting-started)
- [Types of Contributions](#types-of-contributions)
- [Development Setup](#development-setup)
- [Contribution Guidelines](#contribution-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Guidelines](#issue-guidelines)
- [Code Style](#code-style)
- [Security Considerations](#security-considerations)
- [Community](#community)

## 🚀 Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/XSSProbe.git
   cd XSSProbe
   ```
3. **Create a new branch** for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## 🎯 Types of Contributions

We welcome various types of contributions:

### 🔧 Code Contributions
- **Bug fixes**: Fix existing issues or bugs
- **New features**: Add new scanning capabilities or payloads
- **Performance improvements**: Optimize scanning speed or memory usage
- **Error handling**: Improve error detection and handling
- **Cross-platform compatibility**: Ensure compatibility across different OS

### 📚 Documentation
- **README improvements**: Enhance setup and usage instructions
- **Code documentation**: Add docstrings and inline comments
- **Tutorial creation**: Write guides for different use cases
- **FAQ updates**: Add commonly asked questions and answers

### 🧪 Testing
- **Unit tests**: Add test cases for existing functionality
- **Integration tests**: Test complete scanning workflows
- **Edge case testing**: Test with unusual inputs or scenarios

### 🌍 Localization
- **Translation**: Translate documentation or output messages
- **Locale-specific payloads**: Add region-specific XSS payloads

### 🎨 User Experience
- **CLI improvements**: Enhance command-line interface
- **Output formatting**: Improve result presentation
- **Progress indicators**: Add progress bars or status updates

## 🛠️ Development Setup

### Prerequisites
- Python 3.7 or higher
- Git
- Basic understanding of web security concepts

### Installation
```bash
# Clone the repository
git clone https://github.com/hackelite01/XSSProbe.git
cd XSSProbe

# Install dependencies
pip install -r requirements.txt

# Run the tool to test installation
python3 xssprobe.py --help
```

### Running Tests
```bash
# Run basic functionality test
python3 xssprobe.py --about

# Test on a safe target (if available)
python3 xssprobe.py -u http://testphp.vulnweb.com --single
```

## 📝 Contribution Guidelines

### Before Contributing
1. **Check existing issues** to avoid duplicate work
2. **Open an issue** to discuss major changes before implementation
3. **Follow ethical guidelines** - only test on targets you own or have permission to test
4. **Respect rate limits** when testing against web applications

### Code Requirements
- **Python 3.7+ compatibility**: Ensure code works with Python 3.7 and newer
- **Clean code**: Write readable, maintainable code
- **Error handling**: Include proper exception handling
- **Comments**: Add meaningful comments for complex logic
- **No hardcoded values**: Use configuration or constants

### Security Guidelines
- **Responsible disclosure**: Report security issues privately first
- **Safe defaults**: Ensure default settings are safe and ethical
- **Documentation**: Clearly document any potentially dangerous features
- **Legal compliance**: Ensure contributions comply with applicable laws

## 🔄 Pull Request Process

1. **Update documentation** if you're changing functionality
2. **Add tests** for new features when applicable
3. **Ensure your code follows** the existing style
4. **Test thoroughly** on different environments if possible
5. **Write a clear PR description** explaining:
   - What changes you made
   - Why you made them
   - How to test the changes
   - Any breaking changes

### PR Template
When creating a pull request, please include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Other (please describe)

## Testing
- [ ] Tested on local environment
- [ ] Added/updated tests
- [ ] Updated documentation

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No breaking changes (or marked as such)
```

## 🐛 Issue Guidelines

### Before Opening an Issue
1. **Search existing issues** to avoid duplicates
2. **Check the FAQ** in the README
3. **Test with the latest version**

### Bug Reports
Include:
- **Python version** and operating system
- **Command used** when the issue occurred
- **Expected behavior** vs actual behavior
- **Error messages** (full stack trace if available)
- **Steps to reproduce** the issue

### Feature Requests
Include:
- **Clear description** of the feature
- **Use case** - why would this be useful?
- **Proposed implementation** (if you have ideas)
- **Alternatives considered**

### Good First Issues
Look for issues labeled:
- `good first issue` - Perfect for newcomers
- `help wanted` - Community help needed
- `documentation` - Documentation improvements
- `hacktoberfest` - Hacktoberfest-specific issues

## 🎨 Code Style

### Python Style Guide
- Follow **PEP 8** guidelines
- Use **4 spaces** for indentation
- **Line length**: Maximum 100 characters
- **Naming conventions**:
  - Functions: `snake_case`
  - Classes: `PascalCase`
  - Constants: `UPPER_CASE`
  - Variables: `snake_case`

### Import Organization
```python
# Standard library imports
import os
import sys

# Third-party imports
import requests
from bs4 import BeautifulSoup

# Local imports
from lib.helper.helper import *
from lib.core import *
```

### Documentation Style
- Use **docstrings** for all functions and classes
- Include **parameter descriptions** and **return values**
- Add **usage examples** for complex functions

```python
def scan_target(url, payload, method="GET"):
    """
    Scan a target URL for XSS vulnerabilities.
    
    Args:
        url (str): The target URL to scan
        payload (str): XSS payload to test
        method (str): HTTP method to use (GET/POST)
    
    Returns:
        bool: True if vulnerability found, False otherwise
    
    Example:
        >>> scan_target("http://example.com", "<script>alert(1)</script>")
        False
    """
    pass
```

## 🔒 Security Considerations

### Ethical Testing
- **Only test targets you own** or have explicit permission to test
- **Respect robots.txt** and rate limits
- **Don't cause harm** to target applications
- **Use responsible disclosure** for any vulnerabilities found

### Code Security
- **Validate all inputs** to prevent injection attacks
- **Use secure defaults** in configuration
- **Avoid logging sensitive data** like cookies or authentication tokens
- **Handle errors gracefully** without exposing system information

## 👥 Community

### Communication Channels
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community chat
- **Pull Requests**: Code review and collaboration

### Code of Conduct
Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md). We are committed to providing a welcoming and inclusive environment for all contributors.

### Recognition
Contributors will be recognized in:
- **README.md**: Contributors section
- **Release notes**: Major contributions highlighted
- **GitHub**: Contributor graphs and statistics

## 🙏 Thank You

Thank you for contributing to XSSProbe! Your efforts help make web security testing more accessible and effective for everyone.

### Questions?
If you have questions not covered in this guide:
1. Check existing [GitHub Issues](https://github.com/hackelite01/XSSProbe/issues)
2. Open a new issue with the `question` label
3. Join the discussion in [GitHub Discussions](https://github.com/hackelite01/XSSProbe/discussions)

---

**Happy Contributing!** 🎉

Remember: Quality over quantity. A single well-thought-out contribution is worth more than multiple rushed ones.