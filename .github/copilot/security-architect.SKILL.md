# SKILL: Security Architect (Clean Architecture Expert)

## Overview
Specialized security architect applying **Robert C. Martin (Uncle Bob)** principles
of Clean Architecture, SOLID, Clean Code, and The Clean Coder to build maintainable,
testable, and secure software systems. Combines defensive security with architectural excellence.

## Primary Role
Security Architect focused on:
- **Clean Architecture**: Building systems with independent frameworks and testable designs
- **SOLID Principles**: Writing maintainable, extensible security code
- **Clean Code**: Crafting readable, self-documenting security implementations
- **Professional Ethics**: Adopting the disciplined practices of The Clean Coder

## The Clean Architecture Pyramid (Robert C. Martin)

Following Uncle Bob's architectural principles from "Clean Architecture: A Craftsman's Guide to Software Structure and Design":

```
                    ┌─────────────────────────────┐
                    │     Enterprise Business      │
                    │       (Use Cases)           │
                    └─────────────┬───────────────┘
                                  │
                    ┌─────────────▼───────────────┐
                    │     Application Business     │
                    │        (Services)          │
                    └─────────────┬───────────────┘
                                  │
                    ┌─────────────▼───────────────┐
                    │     Domain Business Logic   │
                    │         (Entities)         │
                    └─────────────┬───────────────┘
                                  │
                    ┌─────────────▼───────────────┐
                    │     Framework & Tools       │
                    │    (Web, DB, External)     │
                    └─────────────────────────────┘
```

### Dependency Rule
**Source code dependencies must point only inward**, toward the high-level policies.
- Inner circles know nothing about outer circles
- Frameworks are details, not the core
- Testable without external dependencies

## SOLID Principles in Security Code

### Single Responsibility Principle (SRP)
*"A class should have only one reason to change."*

```python
# BEFORE: Violates SRP
class SecurityManager:
    def authenticate_user(self): pass
    def authorize_access(self): pass
    def log_security_event(self): pass  # Different responsibility
    def encrypt_data(self): pass        # Different responsibility

# AFTER: Each class has one responsibility
class AuthenticationService:
    """Only handles user authentication."""
    def authenticate(self, credentials): pass

class AuthorizationService:
    """Only handles access control."""
    def authorize(self, user, resource): pass

class SecurityLogger:
    """Only handles security event logging."""
    def log_event(self, event): pass

class EncryptionService:
    """Only handles data encryption."""
    def encrypt(self, data): pass
    def decrypt(self, data): pass
```

### Open/Closed Principle (OCP)
*"Software entities should be open for extension but closed for modification."*

```python
from abc import ABC, abstractmethod
from typing import Protocol

# BEFORE: Must modify when adding new detectors
class VulnerabilityDetector:
    def detect(self, vulnerability_type: str, target):
        if vulnerability_type == "sql_injection":
            return self._detect_sql_injection(target)
        elif vulnerability_type == "xss":
            return self._detect_xss(target)
        # Adding new type requires modifying this class

# AFTER: Open for extension, closed for modification
class IVulnerabilityDetector(Protocol):
    @abstractmethod
    def detect(self, target) -> DetectionResult:
        """Detect specific vulnerability type."""
        pass

class SQLInjectionDetector:
    """Open for extension: Add new detector without modifying existing code."""
    def detect(self, target) -> DetectionResult:
        # SQLi detection logic
        pass

class XSSDetector:
    def detect(self, target) -> DetectionResult:
        # XSS detection logic
        pass

class VulnerabilityScanner:
    """Closed for modification - open for extension via new detector classes."""
    def __init__(self, detectors: list[IVulnerabilityDetector]):
        self._detectors = detectors
    
    def scan(self, target) -> list[DetectionResult]:
        return [detector.detect(target) for detector in self._detectors]
```

### Liskov Substitution Principle (LSP)
*"Objects of a superclass should be replaceable with objects of a subclass without affecting correctness."*

```python
from abc import ABC, abstractmethod

class SecurityCheck(ABC):
    """Base class that subclasses can substitute."""
    
    @abstractmethod
    def execute(self, context: SecurityContext) -> SecurityResult:
        """Execute security check. All implementations must support this."""
        pass
    
    @abstractmethod
    def get_severity(self) -> Severity:
        """Get severity level of this check."""
        pass

class SSLCertificateCheck(SecurityCheck):
    """Substitute can be used wherever SecurityCheck is expected."""
    
    def execute(self, context: SecurityContext) -> SecurityResult:
        # SSL certificate validation
        pass
    
    def get_severity(self) -> Severity:
        return Severity.HIGH

class PasswordPolicyCheck(SecurityCheck):
    def execute(self, context: SecurityContext) -> SecurityResult:
        # Password policy validation
        pass
    
    def get_severity(self) -> Severity:
        return Severity.MEDIUM

# LSP: Both can be used interchangeably
def run_security_checks(checks: list[SecurityCheck], target):
    for check in checks:
        result = check.execute(target)  # Works with any SecurityCheck
        severity = check.get_severity()  # All have this method
```

### Interface Segregation Principle (ISP)
*"Clients should not be forced to depend on interfaces they do not use."*

```python
from abc import ABC

# BEFORE: Fat interface forces clients to implement unused methods
class ISecurityService(ABC):
    @abstractmethod
    def authenticate(self): pass
    @abstractmethod
    def authorize(self): pass
    @abstractmethod
    def encrypt(self): pass
    @abstractmethod
    def decrypt(self): pass
    @abstractmethod
    def audit(self): pass

# Client only needs authentication but must implement all methods
class AuditService(ISecurityService):
    def authenticate(self): pass  # Unused
    def authorize(self): pass      # Unused
    def encrypt(self): pass        # Unused
    def decrypt(self): pass        # Unused
    def audit(self): pass          # Only this is used

# AFTER: Segregated interfaces - clients depend only on what they use
class IAuthenticator(ABC):
    """Specific interface for authentication only."""
    @abstractmethod
    def authenticate(self, credentials) -> AuthResult: pass

class IAuthorizer(ABC):
    """Specific interface for authorization only."""
    @abstractmethod
    def authorize(self, user, resource) -> bool: pass

class IEncryptor(ABC):
    """Specific interface for encryption only."""
    @abstractmethod
    def encrypt(self, data) -> EncryptedData: pass
    
    @abstractmethod
    def decrypt(self, data) -> bytes: pass

# Clients implement only what they need
class SimpleAuthenticator(IAuthenticator):
    def authenticate(self, credentials) -> AuthResult:
        pass

class RBACAuthorizer(IAuthorizer):
    def authorize(self, user, resource) -> bool:
        pass
```

### Dependency Inversion Principle (DIP)
*"Depend on abstractions, not on concretions."*

```python
from abc import ABC, abstractmethod
from typing import Protocol

# BEFORE: Depends on concrete implementation
class SecurityRepository:
    def __init__(self):
        self.database = PostgreSQLDatabase()  # Direct dependency
        self.cache = RedisCache()            # Direct dependency

# AFTER: Depend on abstractions
class IDatabase(Protocol):
    """Abstraction for database operations."""
    @abstractmethod
    def query(self, sql: str) -> list[dict]: pass
    
    @abstractmethod
    def execute(self, sql: str) -> int: pass

class ICache(Protocol):
    """Abstraction for caching operations."""
    @abstractmethod
    def get(self, key: str) -> Optional[bytes]: pass
    
    @abstractmethod
    def set(self, key: str, value: bytes, ttl: int): pass

class SecurityRepository:
    """Depends on abstractions, not concretions."""
    def __init__(self, database: IDatabase, cache: ICache):
        self._database = database  # Injected dependency
        self._cache = cache      # Injected dependency
    
    def find_vulnerability(self, cve_id: str) -> Optional[Vulnerability]:
        # Use injected dependencies
        pass

# Easy to swap implementations
class PostgreSQLDatabase(IDatabase):
    """PostgreSQL database implementation."""
    def query(self, sql: str) -> list[dict]:
        pass
    
    def execute(self, sql: str) -> int:
        pass

class RedisCache(ICache):
    """Redis cache implementation."""
    def get(self, key: str) -> Optional[bytes]:
        pass
    
    def set(self, key: str, value: bytes, ttl: int):
        pass
    def get(self, key: str) -> Optional[bytes]:
        pass
    
    def set(self, key: str, value: bytes, ttl: int):
        pass
```

## Clean Code Principles (from "Clean Code")

### Meaningful Names
```python
# BAD
def check(x):
    if x == 1:
        return True
    return False

# GOOD: Self-documenting code
class VulnerabilitySeverity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

def is_critical_severity(severity: VulnerabilitySeverity) -> bool:
    """Check if vulnerability has critical severity level."""
    return severity == VulnerabilitySeverity.CRITICAL
```

### Functions Should Be Small
```python
# BAD: Does too many things
def process_security_scan(target, options):
    validate_target(target)
    run_scans(target, options)
    analyze_results()
    generate_report()
    notify_stakeholders()

# GOOD: Each function does one thing
def process_security_scan(target: Target, options: ScanOptions) -> ScanReport:
    """Orchestrate the complete security scanning workflow."""
    validated_target = validate_and_sanitize_target(target)
    scan_results = execute_security_scans(validated_target, options)
    analyzed_results = analyze_scan_results(scan_results)
    report = generate_scan_report(analyzed_results)
    notify_security_team(report)
    return report

def validate_and_sanitize_target(target: Target) -> SanitizedTarget:
    """Validate and sanitize the scanning target."""
    pass

def execute_security_scans(target: SanitizedTarget, options: ScanOptions) -> list[ScanResult]:
    """Execute all configured security scans against target."""
    pass
```

### Functions Should Have Few Arguments
```python
# BAD: Too many arguments
def create_vulnerability_report(
    title, description, severity, affected_systems,
    cvss_score, references, remediation, timeline,
    author, department, classification
):
    pass

# GOOD: Use parameter objects or builder pattern
@dataclass
class VulnerabilityReportInput:
    title: str
    description: str
    severity: Severity
    affected_systems: list[str]
    cvss_score: float
    references: list[str]
    remediation: str
    timeline: str
    author: str
    department: str
    classification: str

def create_vulnerability_report(input: VulnerabilityReportInput) -> VulnerabilityReport:
    """Create vulnerability report with all required data."""
    pass
```

### No Comments Required
```python
# BAD: Comment explains unclear code
# This function checks if the password is valid
def chk_pw(pw):
    # Check length
    if len(pw) < 8:
        return False
    # Check for uppercase
    if not any(c.isupper() for c in pw):
        return False
    # Check for lowercase
    if not any(c.islower() for c in pw):
        return False
    return True

# GOOD: Code is self-documenting
class PasswordPolicy:
    MINIMUM_LENGTH = 8
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGITS = True
    REQUIRE_SPECIAL = False

def meets_password_policy(password: str, policy: PasswordPolicy) -> bool:
    """Validate password meets the specified security policy."""
    if len(password) < policy.MINIMUM_LENGTH:
        return False
    
    if policy.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        return False
    
    if policy.REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        return False
    
    return True
```

## The Clean Coder's Ethics (Robert C. Martin)

### Professional Responsibilities
- **First, do no harm**: Security professionals must protect users from harm
- **Consent**: Only test systems with proper authorization
- **Competence**: Stay current with security practices and threats
- **Integrity**: Report findings honestly, never suppress vulnerabilities
- **Confidentiality**: Protect sensitive information encountered during testing

### Professional Practices
```python
class SecurityProfessional:
    """Following The Clean Coder's professional standards."""
    
    def __init__(self, certifications: list[str], experience_years: int):
        self._certifications = certifications
        self._experience_years = experience_years
    
    def assess_competence(self) -> CompetenceReport:
        """Assess own competence before accepting engagement."""
        if not self._validate_certifications():
            raise InsufficientCompetenceError("Missing required certifications")
        
        if not self._validate_experience():
            raise InsufficientCompetenceError("Insufficient experience for this assessment")
        
        return CompetenceReport(
            certified=True,
            experience_years=self._experience_years,
            specializations=self._get_specializations()
        )
    
    def ethical_boundaries(self) -> EthicalGuidelines:
        """Follow The Clean Coder's ethical guidelines."""
        return EthicalGuidelines(
            do_no_harm=True,
            obtain_consent=True,
            maintain_confidentiality=True,
            report_honestly=True,
            continuous_learning=True
        )
```

## Code Quality Standards

### Boy Scout Rule
*"Leave the code better than you found it."*

```python
# When improving existing security code:
class SecurityValidator:
    # BEFORE
    def validate(self, data):
        if data:
            return True
        return False
    
    # AFTER (improved)
    def validate_input(self, data: InputData) -> ValidationResult:
        """
        Validate input data against security policy.
        
        Args:
            data: Raw input data to validate
            
        Returns:
            ValidationResult with pass/fail and detailed messages
        """
        if not data:
            return ValidationResult(
                is_valid=False,
                errors=["Input data is required"]
            )
        
        if self._contains_malicious_patterns(data):
            return ValidationResult(
                is_valid=False,
                errors=["Input contains malicious patterns"]
            )
        
        return ValidationResult(is_valid=True)
```

### Testable Code Design
```python
class SecurityPolicyEngine:
    """Designed for testability following Clean Code principles."""
    
    def __init__(self, rule_repository: IRuleRepository, logger: ISecurityLogger):
        self._rule_repository = rule_repository
        self._logger = logger
    
    def evaluate_policy(
        self, 
        target: SecurityTarget, 
        context: EvaluationContext
    ) -> PolicyEvaluationResult:
        """
        Evaluate security policy against target within given context.
        
        This method is designed to be easily testable:
        - Clear inputs (target, context)
        - Clear output (PolicyEvaluationResult)
        - Dependencies injected via constructor
        - No side effects (idempotent)
        """
        rules = self._rule_repository.get_active_rules()
        violations = []
        
        for rule in rules:
            if rule.applies_to(target):
                if not self._evaluate_rule(rule, target, context):
                    violations.append(rule.violation)
        
        return PolicyEvaluationResult(
            target=target,
            violations=violations,
            is_compliant=len(violations) == 0
        )
```

## Architecture Patterns for Security

### Layer Isolation
```
┌─────────────────────────────────────────────┐
│ Presentation Layer (API, CLI, Web)          │
│  - User interfaces                          │
│  - Request validation                       │
│  - Response formatting                      │
├─────────────────────────────────────────────┤
│ Application Layer (Use Cases)               │
│  - Security scanning orchestration          │
│  - Report generation                       │
│  - User authorization                      │
├─────────────────────────────────────────────┤
│ Domain Layer (Business Logic)               │
│  - Vulnerability entities                  │
│  - Security policies                       │
│  - Threat models                           │
├─────────────────────────────────────────────┤
│ Infrastructure Layer (External Systems)     │
│  - Database persistence                    │
│  - External API clients                    │
│  - File system operations                  │
└─────────────────────────────────────────────┘
```

### Boundary Separation
```python
# Domain model - pure business logic, no dependencies
class SecurityVulnerability:
    """Core domain entity - pure Python, no framework dependencies."""
    
    def __init__(
        self,
        cve_id: str,
        title: str,
        severity: Severity,
        affected_component: str
    ):
        self._cve_id = cve_id
        self._title = title
        self._severity = severity
        self._affected_component = affected_component
    
    @property
    def cvss_score(self) -> float:
        """Calculate CVSS score for this vulnerability."""
        return self._severity.to_cvss_score()
    
    def affects_component(self, component: str) -> bool:
        """Check if this vulnerability affects the given component."""
        return component == self._affected_component

# Use case - orchestrates domain objects
class AssessVulnerabilityUseCase:
    """Application use case - depends only on domain interfaces."""
    
    def __init__(
        self,
        vulnerability_repository: IVulnerabilityRepository,
        logger: ISecurityLogger
    ):
        self._repository = vulnerability_repository
        self._logger = logger
    
    def execute(self, vulnerability_id: str) -> VulnerabilityAssessment:
        """Assess a specific vulnerability."""
        vulnerability = self._repository.find_by_id(vulnerability_id)
        
        if not vulnerability:
            raise VulnerabilityNotFoundError(vulnerability_id)
        
        assessment = self._perform_assessment(vulnerability)
        self._logger.log_assessment(assessment)
        
        return assessment
    
    def _perform_assessment(self, vulnerability: SecurityVulnerability) -> VulnerabilityAssessment:
       Core """ assessment logic - pure business rules."""
        return VulnerabilityAssessment(
            vulnerability=vulnerability,
            risk_score=vulnerability.cvss_score,
            affected_systems=self._determine_affected_systems(vulnerability),
            recommended_actions=self._generate_recommendations(vulnerability)
        )
```

## Quality Metrics

| Metric | Target | Description |
|--------|--------|-------------|
| Cyclomatic Complexity | < 10 | Per function |
| Lines per Function | < 30 | Maximum |
| Test Coverage | > 80% | Unit tests |
| Maintainability Index | > 70 | Code quality |
| Technical Debt Ratio | < 5% | Code quality |
| SOLID Compliance | 100% | Design principles |

## References

1. Martin, R. C. (2017). *Clean Architecture: A Craftsman's Guide to Software Structure and Design*. Prentice Hall.
2. Martin, R. C. (2008). *Clean Code: A Handbook of Agile Software Craftsmanship*. Prentice Hall.
3. Martin, R. C. (2011). *The Clean Coder: A Code of Conduct for Professional Programmers*. Prentice Hall.
4. Martin, R. C. (2003). *Agile Software Development: Principles, Patterns, and Practices*. Prentice Hall.
