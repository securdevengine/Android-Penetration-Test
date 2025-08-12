#!/bin/bash
# Android Reverse Engineering Toolkit Setup Script
# This script sets up the complete environment for Android security testing

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   log_error "This script should not be run as root for security reasons"
   exit 1
fi

log_info "Starting Android Reverse Engineering Toolkit setup..."

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    DISTRO=$(lsb_release -si 2>/dev/null || echo "Unknown")
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
else
    log_error "Unsupported operating system: $OSTYPE"
    exit 1
fi

log_info "Detected OS: $OS"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install packages on Linux
install_linux_packages() {
    log_info "Installing Linux dependencies..."
    
    if command_exists apt-get; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y \
            python3 python3-pip python3-venv \
            openjdk-11-jdk \
            android-tools-adb android-tools-fastboot \
            git curl wget unzip \
            build-essential \
            libssl-dev libffi-dev \
            aapt zipalign
    elif command_exists yum; then
        # RHEL/CentOS/Fedora
        sudo yum update -y
        sudo yum install -y \
            python3 python3-pip \
            java-11-openjdk-devel \
            android-tools \
            git curl wget unzip \
            gcc gcc-c++ make \
            openssl-devel libffi-devel
    elif command_exists pacman; then
        # Arch Linux
        sudo pacman -Syu --noconfirm
        sudo pacman -S --noconfirm \
            python python-pip \
            jdk11-openjdk \
            android-tools \
            git curl wget unzip \
            base-devel \
            openssl libffi
    else
        log_error "Unsupported Linux distribution"
        exit 1
    fi
    
    log_success "Linux packages installed"
}

# Function to install packages on macOS
install_macos_packages() {
    log_info "Installing macOS dependencies..."
    
    if ! command_exists brew; then
        log_info "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    brew update
    brew install \
        python3 \
        openjdk@11 \
        android-platform-tools \
        git curl wget unzip \
        openssl libffi
    
    log_success "macOS packages installed"
}

# Install system dependencies
log_info "Installing system dependencies..."

case $OS in
    "linux")
        install_linux_packages
        ;;
    "macos")
        install_macos_packages
        ;;
    "windows")
        log_warning "Windows detected. Please install dependencies manually:"
        log_warning "- Python 3.8+"
        log_warning "- Java JDK 11+"
        log_warning "- Android SDK Platform Tools"
        log_warning "- Git"
        ;;
esac

# Check Python installation
if ! command_exists python3; then
    log_error "Python 3 is not installed or not in PATH"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
log_info "Python version: $PYTHON_VERSION"

# Check Java installation
if ! command_exists java; then
    log_error "Java is not installed or not in PATH"
    exit 1
fi

JAVA_VERSION=$(java -version 2>&1 | head -n 1 | awk -F '"' '{print $2}')
log_info "Java version: $JAVA_VERSION"

# Setup Python virtual environment
log_info "Setting up Python virtual environment..."

if [ ! -d "venv" ]; then
    python3 -m venv venv
    log_success "Virtual environment created"
else
    log_info "Virtual environment already exists"
fi

# Activate virtual environment
source venv/bin/activate || source venv/Scripts/activate 2>/dev/null

# Upgrade pip
python -m pip install --upgrade pip

# Install Python dependencies
log_info "Installing Python dependencies..."
pip install -r requirements.txt
log_success "Python dependencies installed"

# Create tools directory
log_info "Setting up tools directory..."
mkdir -p tools

# Download and setup JADX
log_info "Setting up JADX..."
JADX_VERSION="1.4.7"
JADX_URL="https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"

if [ ! -d "tools/jadx" ]; then
    mkdir -p tools/jadx
    cd tools/jadx
    wget -q "$JADX_URL" -O jadx.zip
    unzip -q jadx.zip
    rm jadx.zip
    chmod +x bin/jadx*
    cd ../..
    log_success "JADX installed"
else
    log_info "JADX already installed"
fi

# Download and setup APKTool
log_info "Setting up APKTool..."
APKTOOL_VERSION="2.7.0"

if [ ! -f "tools/apktool.jar" ]; then
    cd tools
    wget -q "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" -O apktool
    wget -q "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar" -O apktool.jar
    chmod +x apktool
    cd ..
    log_success "APKTool installed"
else
    log_info "APKTool already installed"
fi

# Setup dex2jar
log_info "Setting up dex2jar..."
DEX2JAR_VERSION="2.1"

if [ ! -d "tools/dex2jar" ]; then
    mkdir -p tools/dex2jar
    cd tools/dex2jar
    wget -q "https://github.com/pxb1988/dex2jar/releases/download/v${DEX2JAR_VERSION}/dex-tools-${DEX2JAR_VERSION}.zip" -O dex2jar.zip
    unzip -q dex2jar.zip
    mv dex-tools-${DEX2JAR_VERSION}/* .
    rmdir dex-tools-${DEX2JAR_VERSION}
    rm dex2jar.zip
    chmod +x *.sh
    cd ../..
    log_success "dex2jar installed"
else
    log_info "dex2jar already installed"
fi

# Create output directories
log_info "Creating output directories..."
mkdir -p output/{static_analysis,dynamic_analysis,reports,extracted_data}
mkdir -p logs

# Generate configuration files
log_info "Generating configuration files..."

# Create main config file
cat > config/main_config.json << 'EOF'
{
    "tools": {
        "jadx": "tools/jadx/bin/jadx",
        "apktool": "tools/apktool",
        "dex2jar": "tools/dex2jar/d2j-dex2jar.sh",
        "aapt": "aapt",
        "adb": "adb",
        "frida": "frida"
    },
    "output": {
        "base_dir": "output",
        "static_analysis": "output/static_analysis",
        "dynamic_analysis": "output/dynamic_analysis",
        "reports": "output/reports"
    },
    "frida": {
        "default_scripts": [
            "frida_scripts/ssl_bypass/universal_ssl_bypass.js",
            "frida_scripts/anti_debug/universal_bypass.js"
        ],
        "auto_load": true,
        "timeout": 30
    },
    "analysis": {
        "max_endpoints": 100,
        "max_secrets": 50,
        "timeout": 300
    }
}
EOF

# Create Frida config
cat > config/frida_config.json << 'EOF'
{
    "device": {
        "type": "usb",
        "host": "127.0.0.1",
        "port": 27042
    },
    "scripts": {
        "ssl_bypass": {
            "enabled": true,
            "auto_load": true,
            "path": "frida_scripts/ssl_bypass/universal_ssl_bypass.js"
        },
        "anti_debug": {
            "enabled": true,
            "auto_load": true,
            "path": "frida_scripts/anti_debug/universal_bypass.js"
        },
        "jwt_hook": {
            "enabled": true,
            "auto_load": false,
            "path": "frida_scripts/auth_hooks/jwt_hook.js"
        }
    },
    "options": {
        "spawn_gating": false,
        "child_gating": false,
        "enable_jit": true
    }
}
EOF

# Create Burp Suite config
cat > config/burp_config.json << 'EOF'
{
    "proxy": {
        "host": "127.0.0.1",
        "port": 8080
    },
    "ssl": {
        "ca_cert_path": "config/burp_ca.crt",
        "verify_ssl": false
    },
    "scope": {
        "include_in_scope": [".*"],
        "exclude_from_scope": [
            ".*google.*",
            ".*facebook.*",
            ".*twitter.*"
        ]
    },
    "extensions": {
        "auto_repeater": true,
        "logger_plus_plus": true
    }
}
EOF

# Setup wordlists
log_info "Setting up wordlists..."
mkdir -p wordlists

# Create API endpoints wordlist
cat > wordlists/api_endpoints.txt << 'EOF'
/api/
/api/v1/
/api/v2/
/api/auth/
/api/login
/api/user/
/api/users/
/api/admin/
/api/data/
/api/file/
/api/upload/
/api/download/
/rest/
/service/
/webservice/
/oauth/
/auth/
/login
/signin
/register
/logout
EOF

# Create secrets wordlist
cat > wordlists/android_secrets.txt << 'EOF'
api_key
secret
password
token
auth_token
access_token
refresh_token
jwt_secret
encryption_key
private_key
public_key
app_secret
client_secret
database_password
mysql_password
postgres_password
redis_password
admin_password
root_password
EOF

# Create JWT secrets wordlist
cat > wordlists/jwt_secrets.txt << 'EOF'
secret
password
123456
qwerty
admin
key
jwt_secret
your-256-bit-secret
secret_key
mysecret
test
demo
development
dev
production
prod
app_secret
token_secret
api_secret
default
changeme
please_change_me
insecure
weak
EOF

# Create environment setup script
cat > setup_env.sh << 'EOF'
#!/bin/bash
# Environment setup script - run this before each session

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null
    echo "[+] Virtual environment activated"
else
    echo "[-] Virtual environment not found. Run setup.sh first."
    exit 1
fi

# Add tools to PATH
export PATH="$(pwd)/tools/jadx/bin:$PATH"
export PATH="$(pwd)/tools:$PATH"

# Set Android SDK path if not set
if [ -z "$ANDROID_HOME" ]; then
    if [ -d "$HOME/Android/Sdk" ]; then
        export ANDROID_HOME="$HOME/Android/Sdk"
        export PATH="$ANDROID_HOME/platform-tools:$PATH"
        echo "[+] Android SDK found at $ANDROID_HOME"
    elif [ -d "/opt/android-sdk" ]; then
        export ANDROID_HOME="/opt/android-sdk"
        export PATH="$ANDROID_HOME/platform-tools:$PATH"
        echo "[+] Android SDK found at $ANDROID_HOME"
    else
        echo "[!] Android SDK not found. Please set ANDROID_HOME manually."
    fi
fi

# Check if ADB is working
if command -v adb >/dev/null 2>&1; then
    ADB_DEVICES=$(adb devices | grep -v "List of devices" | wc -l)
    if [ $ADB_DEVICES -gt 0 ]; then
        echo "[+] ADB is working - $ADB_DEVICES device(s) connected"
    else
        echo "[!] No Android devices connected via ADB"
    fi
else
    echo "[-] ADB not found in PATH"
fi

# Check if Frida server is running
if command -v frida-ps >/dev/null 2>&1; then
    if frida-ps -U >/dev/null 2>&1; then
        echo "[+] Frida server is running"
    else
        echo "[!] Frida server not running. Start it with:"
        echo "    adb push frida-server-*-android-* /data/local/tmp/frida-server"
        echo "    adb shell 'chmod 755 /data/local/tmp/frida-server'"
        echo "    adb shell '/data/local/tmp/frida-server &'"
    fi
else
    echo "[-] Frida not installed"
fi

echo "[+] Environment setup complete"
echo ""
echo "Quick start commands:"
echo "  Static analysis:  python scripts/static_analysis/apk_analyzer.py <apk_file>"
echo "  Dynamic analysis: python scripts/dynamic_analysis/frida_automation.py <package_name>"
echo "  JWT analysis:     python scripts/authentication/jwt_analyzer.py <jwt_token>"
echo ""
EOF

chmod +x setup_env.sh

# Create verification script
cat > verify_setup.py << 'EOF'
#!/usr/bin/env python3
"""
Setup Verification Script
Verifies that all components are properly installed and configured.
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, description):
    """Run a command and return success status"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"✓ {description}")
            return True
        else:
            print(f"✗ {description}: {result.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        print(f"✗ {description}: Timeout")
        return False
    except Exception as e:
        print(f"✗ {description}: {e}")
        return False

def check_file_exists(file_path, description):
    """Check if a file exists"""
    if Path(file_path).exists():
        print(f"✓ {description}")
        return True
    else:
        print(f"✗ {description}: File not found")
        return False

def main():
    print("Android Reverse Engineering Toolkit - Setup Verification")
    print("=" * 60)
    
    success_count = 0
    total_checks = 0
    
    # Python checks
    print("\n[Python Environment]")
    total_checks += 1
    if run_command("python --version", "Python 3 available"):
        success_count += 1
    
    total_checks += 1
    if run_command("pip --version", "pip available"):
        success_count += 1
    
    # Java checks
    print("\n[Java Environment]")
    total_checks += 1
    if run_command("java -version", "Java available"):
        success_count += 1
    
    # Android tools
    print("\n[Android Tools]")
    total_checks += 1
    if run_command("adb version", "ADB available"):
        success_count += 1
    
    # Reverse engineering tools
    print("\n[Reverse Engineering Tools]")
    total_checks += 1
    if check_file_exists("tools/jadx/bin/jadx", "JADX installed"):
        success_count += 1
    
    total_checks += 1
    if check_file_exists("tools/apktool", "APKTool installed"):
        success_count += 1
    
    # Python packages
    print("\n[Python Packages]")
    packages = ['frida', 'requests', 'PyJWT', 'cryptography']
    for package in packages:
        total_checks += 1
        if run_command(f"python -c 'import {package}'", f"{package} package"):
            success_count += 1
    
    # Directory structure
    print("\n[Directory Structure]")
    directories = [
        'scripts/static_analysis',
        'scripts/dynamic_analysis', 
        'scripts/authentication',
        'frida_scripts/ssl_bypass',
        'frida_scripts/anti_debug',
        'output',
        'config'
    ]
    
    for directory in directories:
        total_checks += 1
        if check_file_exists(directory, f"{directory}/ directory"):
            success_count += 1
    
    # Summary
    print(f"\n{'='*60}")
    print(f"Verification Results: {success_count}/{total_checks} checks passed")
    
    if success_count == total_checks:
        print("🎉 All checks passed! The toolkit is ready to use.")
        print("\nNext steps:")
        print("1. Run 'source setup_env.sh' to activate the environment")
        print("2. Connect an Android device or start an emulator")
        print("3. Start analyzing APKs!")
        return 0
    else:
        print("⚠️  Some checks failed. Please review the errors above.")
        print("Run setup.sh again or install missing components manually.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
EOF

chmod +x verify_setup.py

# Run verification
log_info "Running setup verification..."
python verify_setup.py

# Final success message
log_success "Setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Run: source setup_env.sh"
echo "2. Connect your Android device or start an emulator"
echo "3. Start reverse engineering!"
echo ""
echo "Quick start examples:"
echo "  Static analysis:  python scripts/static_analysis/apk_analyzer.py sample.apk"
echo "  Dynamic analysis: python scripts/dynamic_analysis/frida_automation.py com.example.app"
echo "  JWT analysis:     python scripts/authentication/jwt_analyzer.py <jwt_token>"
echo ""
echo "Documentation available in docs/"
echo "Happy hacking! 🔐"
