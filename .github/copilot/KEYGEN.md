# KEYGEN Configuration for Minka

## Purpose
This file documents the secure key generation and management practices for Minka,
following Gentlemen Programming principles and Clean Architecture security patterns.

## Security First Approach

### Key Generation Principles
- **Zero-Knowledge Design**: No hardcoded or embedded keys
- **Environment-Based**: All keys loaded from secure environment variables
- **Rotation Ready**: Designed for easy key rotation without code changes
- **Audit Trail**: All key access logged and monitored
- **Principle of Least Privilege**: Keys have minimum necessary permissions

### Environment Variables
Required environment variables (never committed to version control):

```bash
# GitHub Copilot Authentication
GITHUB_TOKEN=ghp_your_personal_access_token_here
GITHUB_USER=your_github_username

# External API Keys (Optional)
SHODAN_API_KEY=your_shodan_key
VIRUSTOTAL_API_KEY=your_virustotal_key
NVD_API_KEY=your_nvd_api_key

# Database Credentials
DB_PASSWORD=secure_database_password
DB_ENCRYPTION_KEY=32_character_encryption_key

# Redis Configuration  
REDIS_PASSWORD=redis_secure_password

# Security Settings
ALLOW_DANGEROUS_OPERATIONS=false
SANDBOX_LEVEL=strict
```

## Key Generation Commands

### GitHub Personal Access Token
```bash
# Generate token with minimum required scopes
gh auth token --scopes "copilot,repo,read:user" --note "Minka-Copilot-SDK"
```

### Database Encryption Key
```bash
# Generate 32-character encryption key
openssl rand -hex 16
```

### Redis Password
```bash
# Generate secure Redis password
openssl rand -base64 32
```

## Secure Configuration Management

### Docker Environment
`.env.example` provided as template (no real keys):
```bash
# Copy template
cp docker/.env.example docker/.env

# Edit with actual keys
vim docker/.env

# Verify no keys committed
echo ".env" >> .gitignore
echo "docker/.env" >> .gitignore
```

### Production Considerations
- Use secret management systems (HashiCorp Vault, AWS Secrets Manager)
- Implement key rotation policies
- Monitor key usage and access patterns
- Enable MFA for all key management operations

## Clean Architecture Implementation

### Configuration Layer
```python
# Domain Layer - Configuration interface
class IConfigManager(ABC):
    @abstractmethod
    def get_copilot_token(self) -> str: pass
    
    @abstractmethod
    def get_database_config(self) -> DatabaseConfig: pass

# Infrastructure Layer - Environment implementation
class EnvironmentConfigManager(IConfigManager):
    def get_copilot_token(self) -> str:
        token = os.getenv('GITHUB_TOKEN')
        if not token or not token.startswith('ghp_'):
            raise ConfigurationError("Invalid GitHub token configuration")
        return token

# Application Layer - Configuration service
class ConfigurationService:
    def __init__(self, config_manager: IConfigManager):
        self._config = config_manager
    
    def get_copilot_client(self) -> CopilotClient:
        token = self._config.get_copilot_token()
        return CopilotClient(token=token)
```

## Security Best Practices

### Never Commit Keys
```bash
# Pre-commit hook to prevent key commits
#!/bin/bash
if git diff --cached --name-only | xargs grep -l "ghp_\|API_KEY\|SECRET" 2>/dev/null; then
    echo "ERROR: Potential secrets detected in staged files!"
    echo "Please remove any keys or secrets before committing."
    exit 1
fi
```

### Token Validation
```python
class TokenValidator:
    @staticmethod
    def validate_github_token(token: str) -> ValidationResult:
        """Validate GitHub token format and presence."""
        if not token:
            return ValidationResult(False, "GitHub token is required")
        
        if not token.startswith(('ghp_', 'github_pat_')):
            return ValidationResult(False, "Invalid GitHub token format")
        
        if len(token) < 20:
            return ValidationResult(False, "Token too short")
        
        return ValidationResult(True, "Token format valid")
```

## Monitoring and Auditing

### Key Access Logging
```python
class SecureConfigManager:
    def __init__(self, logger: ILogger):
        self._logger = logger
        self._audit_log = []
    
    def get_copilot_token(self) -> str:
        token = os.getenv('GITHUB_TOKEN')
        self._log_key_access('GITHUB_TOKEN', 'Token retrieved')
        return token
    
    def _log_key_access(self, key_name: str, action: str):
        """Log all key access attempts."""
        self._audit_log.append({
            'timestamp': datetime.utcnow(),
            'key': key_name,
            'action': action,
            'source': inspect.stack()[1].function
        })
        
        self._logger.info("Key access logged", 
                        key=key_name, 
                        action=action,
                        audit_id=str(uuid.uuid4()))
```

## Documentation Standards

### Configuration Documentation
All configuration options documented with:
- Purpose and description
- Security implications
- Default values
- Required vs optional
- Environment variable names
- Example configurations

### Security Guidelines
- Only store keys in environment variables
- Rotate keys regularly
- Use minimal privilege principle
- Monitor key usage patterns
- Implement revocation procedures
- Document key lifecycle management

## Gentlemen Programming Approach

### Professional Standards
- Clear documentation of security practices
- Respect for user privacy and data
- Ethical key management
- Responsible disclosure procedures
- Continuous security improvement

### Code Quality
- No hardcoded values
- Clear error messages
- Comprehensive logging
- Type safety in configuration
- Testability of security controls