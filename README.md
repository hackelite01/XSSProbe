  
## A powerful XSS scanner made in python 3<br/>
[![CodeFactor](https://www.codefactor.io/repository/github/hackelite01/xssprobe/badge)](https://www.codefactor.io/repository/github/hackelite01/xssprobe)

<img src="xssprobe.png">

## 📦 Installation

### Prerequisites
- **Python 3.7+** - [Download Python](https://www.python.org/downloads/)
- **Git** - [Download Git](https://git-scm.com/downloads/)
- **Docker** (Optional) - [Download Docker](https://www.docker.com/get-started)

## 🚀 Installation Methods

### Method 1: Git Clone (Recommended)

```bash
# Clone the repository
git clone https://github.com/adityanageshsir/XSSProbe.git

# Navigate to the project directory
cd XSSProbe

# Install dependencies
pip install -r requirements.txt

# Make the script executable (Linux/macOS)
chmod +x xssprobe.py

# Verify installation
python3 xssprobe.py --help
```

### Method 2: Docker Installation 🐳

```bash
# Build Docker image
docker build -t xssprobe .

# Run XSSProbe in container
docker run --rm -it xssprobe -u https://example.com

# Run with custom options
docker run --rm -it xssprobe -u https://example.com --depth 3 --dom-xss

# Run with volume mapping for results
docker run --rm -it -v $(pwd)/results:/app/results xssprobe -u https://example.com
```

**Docker Compose:**
```yaml
version: '3.8'
services:
  xssprobe:
    build: .
    volumes:
      - ./results:/app/results
    command: ["python3", "xssprobe.py", "-u", "https://example.com"]
```

### Method 3: Pip Install (Coming Soon)

```bash
# Install from PyPI (Future release)
pip install xssprobe

# Run directly
xssprobe -u https://example.com
```

### Method 4: Virtual Environment Setup

#### 🐧 Linux/macOS
```bash
# Create virtual environment
python3 -m venv xssprobe-env

# Activate virtual environment
source xssprobe-env/bin/activate

# Clone and install
git clone https://github.com/adityanageshsir/XSSProbe.git
cd XSSProbe
pip install -r requirements.txt

# Deactivate when done
deactivate
```

#### 🪟 Windows
```cmd
# Create virtual environment
python -m venv xssprobe-env

# Activate virtual environment
xssprobe-env\Scripts\activate

# Clone and install
git clone https://github.com/adityanageshsir/XSSProbe.git
cd XSSProbe
pip install -r requirements.txt

# Deactivate when done
deactivate
```

#### Using Conda
```bash
# Create conda environment
conda create -n xssprobe python=3.9

# Activate environment
conda activate xssprobe

# Install dependencies
pip install -r requirements.txt

# Deactivate when done
conda deactivate
```

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| beautifulsoup4 | ≥ 4.9.0 | HTML parsing and analysis |
| requests | ≥ 2.25.0 | HTTP request handling |
| urllib3 | ≥ 1.26.0 | URL parsing and utilities |

**Manual dependency installation:**
```bash
pip install beautifulsoup4>=4.9.0 requests>=2.25.0 urllib3>=1.26.0
```

## 🛠️ Platform-Specific Installation

### 🐧 Linux (Ubuntu/Debian)

```bash
# Update package manager
sudo apt update

# Install Python and dependencies
sudo apt install python3 python3-pip python3-venv git

# Install build tools (if needed)
sudo apt install build-essential python3-dev

# Clone and setup XSSProbe
git clone https://github.com/adityanageshsir/XSSProbe.git
cd XSSProbe
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 🎩 Linux (CentOS/RHEL/Fedora)

```bash
# CentOS/RHEL
sudo yum install python3 python3-pip git
# OR for newer versions
sudo dnf install python3 python3-pip git

# Install XSSProbe
git clone https://github.com/adityanageshsir/XSSProbe.git
cd XSSProbe
pip3 install --user -r requirements.txt
```

### 🍎 macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and Git
brew install python@3.9 git

# Install XSSProbe
git clone https://github.com/adityanageshsir/XSSProbe.git
cd XSSProbe
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 🪟 Windows

#### Option 1: Windows Store
```powershell
# Install Python from Microsoft Store
# Search for "Python 3.9" in Microsoft Store

# Install Git
winget install Git.Git

# Install XSSProbe
git clone https://github.com/adityanageshsir/XSSProbe.git
cd XSSProbe
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

#### Option 2: Chocolatey
```powershell
# Install Chocolatey (if not installed)
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install Python and Git
choco install python git

# Install XSSProbe
git clone https://github.com/adityanageshsir/XSSProbe.git
cd XSSProbe
pip install -r requirements.txt
```

## 🔧 Troubleshooting

### Common Installation Issues

#### ❌ Python Version Conflicts
```bash
# Check Python version
python3 --version
python --version

# Use specific Python version
python3.9 -m pip install -r requirements.txt

# Update Python PATH (Windows)
# Add C:\Python39 and C:\Python39\Scripts to PATH
```

#### ❌ Permission Denied Errors

**Linux/macOS:**
```bash
# Use --user flag
pip install --user -r requirements.txt

# Or fix permissions
sudo chown -R $USER ~/.local/
```

**Windows:**
```cmd
# Run as Administrator
# Right-click Command Prompt > "Run as administrator"

# Or install to user directory
pip install --user -r requirements.txt
```

#### ❌ SSL Certificate Issues
```bash
# Corporate networks/proxy
pip install -r requirements.txt --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org

# Update certificates
pip install --upgrade certifi

# Set certificate path
export SSL_CERT_FILE=$(python -m certifi)
```

#### ❌ Proxy Configuration
```bash
# Set proxy for pip
pip install -r requirements.txt --proxy http://proxy.company.com:8080

# Set proxy environment variables
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=https://proxy.company.com:8080
```

#### ❌ Module Import Errors
```bash
# Verify installation
python3 -c "import requests, bs4; print('Dependencies OK')"

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Check Python path
python3 -c "import sys; print(sys.path)"
```

#### ❌ Docker Issues
```bash
# Docker permission denied (Linux)
sudo usermod -aG docker $USER
# Logout and login again

# Docker build fails
docker system prune -f
docker build --no-cache -t xssprobe .

# Container networking issues
docker run --network host xssprobe -u https://example.com
```

### Platform-Specific Issues

#### 🐧 Linux Issues
```bash
# Missing headers
sudo apt install python3-dev libffi-dev libssl-dev

# SELinux issues (CentOS/RHEL)
sudo setsebool -P httpd_can_network_connect 1
```

#### 🍎 macOS Issues
```bash
# Xcode command line tools
xcode-select --install

# Homebrew Python conflicts
brew unlink python@3.8 && brew link python@3.9
```

#### 🪟 Windows Issues
```cmd
# Long path support
reg add HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1

# Execution policy (PowerShell)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## ✅ Verify Installation

```bash
# Basic verification
python3 xssprobe.py --help

# Test with safe target
python3 xssprobe.py --about

# Quick functionality test
python3 xssprobe.py --single https://httpbin.org/forms/post
```

**Expected output:**
```
[INFO] XSSProbe v1.0 - Advanced XSS Scanner
[INFO] GitHub: https://github.com/adityanageshsir/XSSProbe
[INFO] Python version: 3.9.x
[INFO] Dependencies: OK
```
## Usage
Basic usage:

```bash
python3 xssprobe.py -u http://testphp.vulnweb.com
```
<br/>
Advanced usage:

```bash
python3 xssprobe.py --help
```

## Main features

* crawling all links on a website ( crawler engine )
* POST and GET forms are supported
* many settings that can be customized
* Advanced error handling
* Multiprocessing support.
* And many more..

## Note
* Currently it doesn't support DOM!

