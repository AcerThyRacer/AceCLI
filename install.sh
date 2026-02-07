#!/bin/bash
# ============================================================
#  AceCLI Installer for Linux/macOS
#  Usage: curl -fsSL <url> | bash
#     or: chmod +x install.sh && ./install.sh
# ============================================================
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║       AceCLI Installer (Linux)       ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${NC}"

# 1. Check Node.js
if ! command -v node &> /dev/null; then
  echo -e "${RED}✗ Node.js not found.${NC}"
  echo "  Install Node.js 18+ from https://nodejs.org"
  echo "  Or run: curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs"
  exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
  echo -e "${RED}✗ Node.js 18+ required (found v$(node -v))${NC}"
  exit 1
fi
echo -e "${GREEN}✓ Node.js $(node -v)${NC}"

# 2. Check npm
if ! command -v npm &> /dev/null; then
  echo -e "${RED}✗ npm not found.${NC}"
  exit 1
fi
echo -e "${GREEN}✓ npm $(npm -v)${NC}"

# 3. Check git
if ! command -v git &> /dev/null; then
  echo -e "${RED}✗ git not found. Install git first.${NC}"
  exit 1
fi
echo -e "${GREEN}✓ git $(git --version | awk '{print $3}')${NC}"

# 4. Clone repo
INSTALL_DIR="$HOME/.acecli"
if [ -d "$INSTALL_DIR" ]; then
  echo -e "${YELLOW}→ Updating existing installation...${NC}"
  cd "$INSTALL_DIR"
  git pull --ff-only
else
  echo -e "${YELLOW}→ Cloning AceCLI...${NC}"
  git clone https://github.com/AcerThyRacer/AceCLI.git "$INSTALL_DIR"
  cd "$INSTALL_DIR"
fi

# 5. Install dependencies
echo -e "${YELLOW}→ Installing dependencies...${NC}"
npm install --production

# 6. Link globally
echo -e "${YELLOW}→ Linking 'ace' command globally...${NC}"
npm link 2>/dev/null || sudo npm link

# 7. Verify
if command -v ace &> /dev/null; then
  echo ""
  echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║    AceCLI installed successfully!    ║${NC}"
  echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
  echo ""
  echo "  Run:  ace"
  echo "  Help: ace --help"
  echo ""
else
  echo ""
  echo -e "${GREEN}✓ AceCLI installed to ${INSTALL_DIR}${NC}"
  echo "  Run directly: node ${INSTALL_DIR}/src/index.js"
  echo "  Or add to PATH: export PATH=\"\$PATH:${INSTALL_DIR}/bin\""
  echo ""
fi
