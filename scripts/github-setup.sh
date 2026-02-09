#!/bin/bash
# Initialize Git and Create GitHub Repository
# Script to set up Git repository and push to GitHub

set -e

echo "🐙 Minka GitHub Setup Script"
echo "============================"
echo ""

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Get GitHub username
read -p "Enter your GitHub username: " GITHUB_USER

# Repository name
REPO_NAME="minka"

# Full repository URL
REPO_URL="https://github.com/$GITHUB_USER/$REPO_NAME.git"

echo ""
echo -e "${YELLOW}Configuring Git repository...${NC}"
echo ""

# Initialize git if not already initialized
if [ ! -d ".git" ]; then
    git init
    echo -e "${GREEN}✓ Git repository initialized${NC}"
else
    echo -e "${YELLOW}⚠ Git repository already exists${NC}"
fi

# Configure git (if not set)
if [ -z "$(git config user.name)" ]; then
    read -p "Enter your name for git commits: " GIT_NAME
    git config user.name "$GIT_NAME"
    echo -e "${GREEN}✓ Git user name configured${NC}"
fi

if [ -z "$(git config user.email)" ]; then
    read -p "Enter your email for git commits: " GIT_EMAIL
    git config user.email "$GIT_EMAIL"
    echo -e "${GREEN}✓ Git user email configured${NC}"
fi

# Create .gitignore if not exists
if [ ! -f ".gitignore" ]; then
    cp .gitignore .gitignore.bak 2>/dev/null || true
fi

# Add all files
echo ""
echo -e "${YELLOW}Staging files...${NC}"
git add -A

# Show staged files
echo ""
echo "Files to be committed:"
git status --short

# Create initial commit
echo ""
read -p "Enter commit message (or press Enter for default): " COMMIT_MSG

if [ -z "$COMMIT_MSG" ]; then
    COMMIT_MSG="feat: Initial commit - Minka Cybersecurity Assistant

- Clean Architecture based on Uncle Bob principles
- SOLID principles applied to security code  
- Professional ethics from The Clean Coder
- GitHub Copilot SDK integration
- 4 specialized agents: Vuln Researcher, Red Team, OSINT, Architect
- Docker multi-container setup with vulnerable labs
- Educational focus for UCM Cybersecurity Master"
fi

git commit -m "$COMMIT_MSG"
echo -e "${GREEN}✓ Initial commit created${NC}"

# Create GitHub repository
echo ""
echo -e "${YELLOW}Creating GitHub repository...${NC}"

# Check if gh CLI is available
if command -v gh &> /dev/null; then
    # Create repository using gh CLI
    gh repo create "$REPO_NAME" --public --description "Cybersecurity Assistant with Clean Architecture, SOLID principles & GitHub Copilot SDK - Built for UCM Cybersecurity Master"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ GitHub repository created: $REPO_URL${NC}"
        
        # Add remote
        git remote add origin "$REPO_URL" 2>/dev/null || true
        echo -e "${GREEN}✓ Remote 'origin' added${NC}"
        
        # Push to GitHub
        echo ""
        echo -e "${YELLOW}Pushing to GitHub...${NC}"
        git push -u origin main
        
        echo ""
        echo -e "${GREEN}🎉 Successfully pushed to GitHub!${NC}"
        echo ""
        echo "Repository URL: https://github.com/$GITHUB_USER/$REPO_NAME"
    else
        echo -e "${RED}✗ Failed to create repository${NC}"
        echo ""
        echo "Manual steps:"
        echo "1. Create repository at: https://github.com/new"
        echo "2. Run: git remote add origin $REPO_URL"
        echo "3. Run: git push -u origin main"
    fi
else
    echo -e "${YELLOW}⚠ GitHub CLI (gh) not found${NC}"
    echo ""
    echo "Manual steps:"
    echo "1. Create repository at: https://github.com/new"
    echo "2. Run: git remote add origin $REPO_URL"
    echo "3. Run: git push -u origin main"
fi

echo ""
echo "================================"
echo "✅ Setup complete!"
echo "================================"
echo ""
echo "Next steps:"
echo "  1. Configure your GitHub token in docker/.env"
echo "  2. Run: docker-compose -f docker/docker-compose.yml up -d"
echo "  3. Test: minka start"
echo ""
echo "Good luck! 🛡️"
