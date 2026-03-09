# BCC Tool Deployment Plan
> Deploy a BCC Python script as a curl-installable CLI tool hosted on GitHub

---

## 1. Repository Structure

Set up the GitHub repo with the following layout:

```
your-tool/
├── your_tool.py        # Main BCC script (no .py in the installed binary name)
├── install.sh          # Curl-installable bash installer
├── uninstall.sh        # Optional cleanup script
├── README.md           # Usage docs + install instructions
└── .github/
    └── workflows/
        └── lint.yml    # Optional: shell/python linting CI
```

---

## 2. Prepare the BCC Script

### 2.1 Add a shebang
The very first line of `your_tool.py` must be:
```python
#!/usr/bin/env python3
```
This is what allows the OS to run it without the `python3` prefix.

### 2.2 Root check
BCC tools require root. Add this early in the script:
```python
import os, sys

if os.geteuid() != 0:
    print("Error: this tool must be run as root (sudo your-tool)", file=sys.stderr)
    sys.exit(1)
```

### 2.3 Kernel version guard (optional but recommended)
```python
import platform

def check_kernel():
    major, minor, *_ = platform.release().split(".")
    if int(major) < 4 or (int(major) == 4 and int(minor) < 9):
        print("Error: kernel >= 4.9 required for BCC", file=sys.stderr)
        sys.exit(1)

check_kernel()
```

---

## 3. Write the Installer (`install.sh`)

### 3.1 Skeleton
```bash
#!/usr/bin/env bash
set -euo pipefail

TOOL_NAME="your-tool"
INSTALL_DIR="/usr/local/bin"
RAW_URL="https://raw.githubusercontent.com/YOUR_USER/YOUR_REPO/main/your_tool.py"

# --- Privilege check ---
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root: curl ... | sudo bash"
  exit 1
fi

# --- Distro detection ---
detect_os() {
  [ -f /etc/os-release ] && . /etc/os-release && echo "$ID" || echo "unknown"
}

# --- Dependency installation ---
install_deps() {
  local os
  os=$(detect_os)
  echo "[*] Detected OS: $os"

  case "$os" in
    ubuntu|debian|linuxmint|pop)
      apt-get update -qq
      apt-get install -y \
        python3-bpfcc \
        bpfcc-tools \
        linux-headers-"$(uname -r)"
      ;;
    fedora)
      dnf install -y bcc-tools python3-bcc kernel-devel-"$(uname -r)"
      ;;
    centos|rhel|rocky|almalinux)
      yum install -y bcc-tools python3-bcc kernel-devel
      ;;
    arch|manjaro)
      pacman -Sy --noconfirm python-bcc bcc-tools linux-headers
      ;;
    *)
      echo "Unsupported distro: $os"
      echo "Manually install: bcc-tools, python3-bcc, linux-headers"
      exit 1
      ;;
  esac
}

# --- Download and install ---
install_tool() {
  echo "[*] Downloading $TOOL_NAME..."
  curl -fsSL "$RAW_URL" -o "$INSTALL_DIR/$TOOL_NAME"
  chmod +x "$INSTALL_DIR/$TOOL_NAME"
  echo "[✓] Installed: $INSTALL_DIR/$TOOL_NAME"
  echo "    Usage: sudo $TOOL_NAME"
}

# --- Entry point ---
install_deps
install_tool
```

### 3.2 Checklist before publishing
- [ ] Replace `YOUR_USER`, `YOUR_REPO`, and `your_tool.py` with real values
- [ ] Test on a clean VM for each distro (see Section 6)
- [ ] Pin to a specific git tag/commit in `RAW_URL` for production stability

---

## 4. Write the Uninstaller (`uninstall.sh`)

```bash
#!/usr/bin/env bash
set -euo pipefail

TOOL_NAME="your-tool"
INSTALL_DIR="/usr/local/bin"

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

if [ -f "$INSTALL_DIR/$TOOL_NAME" ]; then
  rm -f "$INSTALL_DIR/$TOOL_NAME"
  echo "[✓] Removed $INSTALL_DIR/$TOOL_NAME"
else
  echo "[!] $TOOL_NAME not found in $INSTALL_DIR"
fi
```

---

## 5. Write the README

The README should include, at minimum:

```markdown
## Install

\`\`\`bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USER/YOUR_REPO/main/install.sh | sudo bash
\`\`\`

## Usage

\`\`\`bash
sudo your-tool [options]
\`\`\`

## Uninstall

\`\`\`bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USER/YOUR_REPO/main/uninstall.sh | sudo bash
\`\`\`

## Requirements

- Linux kernel >= 4.9
- Root/sudo access
- Supported distros: Ubuntu/Debian, Fedora, RHEL/CentOS, Arch
```

---



## 8. Delivery Summary

| Artifact       | Purpose                            |
|----------------|------------------------------------|
| `your_tool.py` | The BCC script (acts as the binary)|
| `install.sh`   | Installs deps + places script in PATH |
| `uninstall.sh` | Removes the tool cleanly           |
| `README.md`    | Docs with one-liner install command|

**Final user experience:**
```bash
# Install
curl -fsSL https://raw.githubusercontent.com/YOUR_USER/YOUR_REPO/main/install.sh | sudo bash

# Run
sudo your-tool

# Remove
curl -fsSL https://raw.githubusercontent.com/YOUR_USER/YOUR_REPO/main/uninstall.sh | sudo bash
```