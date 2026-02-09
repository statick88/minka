# Contributing to Minka

Thank you for your interest in contributing to Minka! This document provides guidelines and instructions for contributing.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contribution Guidelines](#contribution-guidelines)
- [Submitting Changes](#submitting-changes)
- [Style Guidelines](#style-guidelines)

---

## 📜 Code of Conduct

This project follows our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

### Our Standards

- ✅ Be respectful and inclusive
- ✅ Use welcoming language
- ✅ Accept constructive criticism
- ✅ Focus on what is best for the community
- ✅ Show empathy towards other community members

### Unacceptable Behavior

- ❌ Harassment or discrimination
- ❌ Trolling or insulting comments
- ❌ Personal attacks
- ❌ Publishing private information

---

## 🚀 Getting Started

### Types of Contributions

1. **🐛 Bug Reports** - Report issues you find
2. **💡 Feature Requests** - Suggest new features
3. **📝 Documentation** - Improve or translate docs
4. **🔧 Code Contributions** - Fix bugs or add features
5. **🧪 Testing** - Improve test coverage

---

## 💻 Development Setup

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- GitHub Copilot subscription
- Git

### Initial Setup

```bash
# Fork the repository on GitHub

# Clone your fork
git clone https://github.com/YOUR-USERNAME/minka.git
cd minka

# Add upstream remote
git remote add upstream https://github.com/original-owner/minka.git

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If exists

# Install pre-commit hooks
pre-commit install

# Create a new branch for your work
git checkout -b feature/your-feature-name
```

---

## 📝 Contribution Guidelines

### 1. Finding Issues

- Check [Issues](https://github.com/your-org/minka/issues) for open issues
- Look for `good first issue` tags for beginners
- Ask to be assigned to an issue before starting

### 2. Branch Naming

```
feature/description-of-feature      # New features
bugfix/description-of-bugfix         # Bug fixes
hotfix/description-of-hotfix          # Urgent fixes
docs/improvement-description         # Documentation updates
refactor/code-quality-improvement   # Code improvements
```

### 3. Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: Add new vulnerability scanner
fix: Fix CVE lookup timeout issue
docs: Update installation guide
style: Fix linting errors
refactor: Apply SOLID principles to SecurityManager
test: Add unit tests for VulnResearcherAgent
chore: Update dependencies
```

### 4. Pull Request Process

1. **Before submitting**:
   - Run tests: `pytest`
   - Run linters: `ruff check src/`
   - Run type checks: `mypy src/`
   - Update documentation as needed

2. **Submit PR**:
   - Fill out the PR template
   - Link related issues
   - Request review from maintainers

3. **After review**:
   - Address feedback
   - Squash commits if needed
   - Ensure CI passes

---

## ✅ Submitting Changes

### PR Checklist

- [ ] Tests added/updated
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] All CI checks pass
- [ ] At least one approval from maintainer

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
How was this tested?

## Screenshots (if applicable)
Add screenshots here

## Checklist
- [ ] My code follows the style guidelines
- [ ] I have performed a self-review
- [ ] I have commented my code
- [ ] I have made corresponding changes
- [ ] I have added tests
- [ ] New and existing tests pass
```

---

## 🎨 Style Guidelines

### Python Code (PEP 8)

We use `ruff` for linting:

```bash
# Run linter
ruff check src/

# Auto-fix
ruff check --fix src/
```

### Type Hints

All functions must have type hints:

```python
# GOOD
def authenticate_user(self, username: str, password: str) -> bool:
    """Authenticate a user."""
    pass

# BAD
def authenticate_user(username, password):
    pass
```

### Clean Code Principles

Following Robert C. Martin:

1. **Meaningful Names**
   ```python
   # GOOD
   vulnerability_severity = "CRITICAL"
   def authenticate_user(credentials): pass
   
   # BAD
   x = "C"
   def chk(u, p): pass
   ```

2. **Small Functions**
   ```python
   # GOOD - Each function does one thing
   def validate_password(password: str) -> bool:
       if len(password) < 8:
           return False
       return True
   
   # BAD - Too many responsibilities
   def validate_and_save_and_notify(data):
       # Everything...
   ```

3. **Comments Explain WHY**
   ```python
   # GOOD - Explains why
   # Using modified CVSS because asset valuations differ
   def calculate_risk(): pass
   
   # BAD - Explains what (code already shows this)
   def get_user():
       # Get user from database
   ```

### SOLID Principles

All code must follow SOLID principles:

- **S**ingle Responsibility
- **O**pen/Closed
- **L**iskov Substitution
- **I**nterface Segregation
- **D**ependency Inversion

### Documentation

Use docstrings (Google style):

```python
def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate a user with username and password.

    Args:
        username: The user's username
        password: The user's password

    Returns:
        True if authentication successful, False otherwise

    Raises:
        AuthenticationError: If credentials are invalid
    """
    pass
```

---

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test
pytest tests/unit/test_client.py -v
```

### Writing Tests

```python
import pytest

class TestVulnerabilityScanner:
    """Tests for VulnerabilityScanner class."""
    
    def test_scan_returns_vulnerabilities(self, scanner, sample_target):
        """Test that scan finds expected vulnerabilities."""
        result = scanner.scan(sample_target)
        assert result is not None
        assert len(result.vulnerabilities) > 0
    
    def test_scan_handles_errors_gracefully(self, scanner, unreachable_target):
        """Test that scan handles errors without crashing."""
        result = scanner.scan(unreachable_target)
        assert result.error is not None
```

---

## 📚 Additional Resources

- [Architecture Guide](docs/architecture.md)
- [API Documentation](docs/api/README.md)
- [Clean Architecture Reference](.github/copilot/QUICK-REFERENCE.md)
- [Robert C. Martin's Books](https://www.amazon.com/stores/Robert-C.-Martin)

---

## 💬 Questions?

- Open an [Issue](https://github.com/your-org/minka/issues)
- Join our [Discord](https://discord.gg/your-invite) (if exists)
- Email: maintainers@minka.local

---

Thank you for contributing to Minka! 🎉
