#!/bin/bash

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Define venv name - change this to your preferred name
VENV_NAME="venv"

echo -e "${YELLOW}Checking for Python...${NC}"
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}Python 3 is not installed! Please install Python 3 first.${NC}"
    exit 1
fi

# Check if venv module is available
echo -e "${YELLOW}Checking for venv module...${NC}"
if ! python3 -m venv --help &>/dev/null; then
    echo -e "${YELLOW}Python venv module not found. Attempting to install...${NC}"
    
    # Try to detect the OS and install venv accordingly
    if command -v apt-get &>/dev/null; then
        echo -e "${YELLOW}Debian/Ubuntu detected. Installing python3-venv...${NC}"
        sudo apt-get update && sudo apt-get install -y python3-venv
    elif command -v dnf &>/dev/null; then
        echo -e "${YELLOW}Fedora/RHEL detected. Installing python3-venv...${NC}"
        sudo dnf install -y python3-venv
    elif command -v yum &>/dev/null; then
        echo -e "${YELLOW}CentOS/RHEL detected. Installing python3-venv...${NC}"
        sudo yum install -y python3-venv
    elif command -v pacman &>/dev/null; then
        echo -e "${YELLOW}Arch Linux detected. Installing python-virtualenv...${NC}"
        sudo pacman -S --noconfirm python-virtualenv
    elif command -v brew &>/dev/null; then
        echo -e "${YELLOW}macOS with Homebrew detected. Ensuring Python has venv...${NC}"
        brew install python
    else
        echo -e "${RED}Unable to detect package manager. Please install Python venv module manually.${NC}"
        exit 1
    fi
    
    # Verify installation
    if ! python3 -m venv --help &>/dev/null; then
        echo -e "${RED}Failed to install venv module. Please install it manually.${NC}"
        exit 1
    fi
fi

# Check if venv already exists
if [ -d "$VENV_NAME" ]; then
    echo -e "${YELLOW}Virtual environment '$VENV_NAME' already exists.${NC}"
    
    # Offer to reuse or recreate
    read -p "Do you want to reuse it? (y/n): " choice
    case "$choice" in
        y|Y|yes|Yes)
            echo -e "${GREEN}Reusing existing virtual environment.${NC}"
            ;;
        *)
            echo -e "${YELLOW}Removing existing virtual environment...${NC}"
            rm -rf "$VENV_NAME"
            echo -e "${YELLOW}Creating new virtual environment...${NC}"
            python3 -m venv "$VENV_NAME"
            ;;
    esac
else
    # Create venv
    echo -e "${YELLOW}Creating virtual environment '$VENV_NAME'...${NC}"
    python3 -m venv "$VENV_NAME"
fi

source "$VENV_NAME/bin/activate"

# Install packages from requirements.txt if it exists
if [ -f "requirement.txt" ]; then
    echo -e "${YELLOW}Installing packages from requirements.txt...${NC}"
    pip install -r requirement.txt
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Successfully installed packages from requirement.txt${NC}"
    else
        echo -e "${RED}Failed to install some packages from requirement.txt${NC}"
    fi
else
    echo -e "${YELLOW}No requirement.txt file found. Skipping package installation.${NC}"
fi

# Install BPF and kernel headers
echo -e "${YELLOW}Installing BPF tools and kernel headers...${NC}"
if command -v apt-get &>/dev/null; then
    sudo apt-get update && sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r)
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Successfully installed BPF tools and kernel headers${NC}"
    else
        echo -e "${RED}Failed to install BPF tools and kernel headers${NC}"
    fi
else
    echo -e "${YELLOW}Not using apt package manager. Please install BPF tools manually for your distribution.${NC}"
fi

# Make scripts executable
echo -e "${YELLOW}Making scripts executable...${NC}"
if [ -f "./runner.sh" ]; then
    chmod +x ./runner.sh
    echo -e "${GREEN}Made runner.sh executable${NC}"
else
    echo -e "${YELLOW}runner.sh not found, skipping${NC}"
fi

if [ -f "./tracer.py" ]; then
    chmod +x ./tracer.py
    echo -e "${GREEN}Made tracer.py executable${NC}"
else
    echo -e "${YELLOW}tracer.py not found, skipping${NC}"
fi

if [ -f "./analyzer.py" ]; then
    chmod +x ./analyzer.py
    echo -e "${GREEN}Made analyzer.py executable${NC}"
else
    echo -e "${YELLOW}analyzer.py not found, skipping${NC}"
fi

# Verify activation
if [ "$VIRTUAL_ENV" != "" ]; then
    echo -e "${GREEN}Success! Virtual environment is activated.${NC}"
    echo -e "${GREEN}Python version: $(python --version)${NC}"
    echo -e "${GREEN}Pip version: $(pip --version)${NC}"
    echo -e "${YELLOW}NOTE: This virtual environment will only remain active in this terminal session.${NC}"
    echo -e "${YELLOW}NEXT STEP, run:"
    echo -e "->\tsource $VENV_NAME/bin/activate${NC}"
    echo -e "${YELLOW}To deactivate, simply run: deactivate${NC}"
else
    echo -e "${RED}Failed to activate virtual environment.${NC}"
    exit 1
fi