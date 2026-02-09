# Clean Architecture Reference Card

## The Dependency Rule
> "Source code dependencies must point only inward."

```
Most Important Rule in Clean Architecture

     ┌─────────────────────────────────────┐
     │     Enterprise Business Rules        │
     │        (Use Cases / Services)        │
     └──────────────┬──────────────────────┘
                    │
     ┌──────────────▼──────────────────────┐
     │     Application Business Rules       │
     │        (Use Case Orchestration)     │
     └──────────────┬──────────────────────┘
                    │
     ┌──────────────▼──────────────────────┐
     │         Domain Entities              │
     │    (Business Objects / Models)      │
     └──────────────┬──────────────────────┘
                    │
     ┌──────────────▼──────────────────────┐
     │     Framework & Tools Layer          │
     │  (DB, Web, External Services, etc.)  │
     └─────────────────────────────────────┘

    Dependencies ALWAYS point INWARD
```

---

## SOLID Principles Quick Reference

### S - Single Responsibility
```python
# ONE reason to change
class User: pass              # Data
class UserRepository: pass     # Persistence
class UserAuthenticator: pass  # Auth logic
class UserLogger: pass         # Logging
# NOT one class doing all four
```

### O - Open/Closed
```python
# OPEN: Extend with new classes
# CLOSED: Don't modify existing code

class VulnerabilityDetector: pass
class SQLInjectionDetector(VulnerabilityDetector): pass
class XSSDetector(VulnerabilityDetector): pass
# Add new detectors without modifying base
```

### L - Liskov Substitution
```python
# Subclasses must work where base class works

class SecurityCheck: pass
class SSLCheck(SecurityCheck): pass  # Can substitute SecurityCheck
class AuthCheck(SecurityCheck): pass  # Can substitute SecurityCheck

# All SecurityCheck subclasses are interchangeable
def run_checks(checks: list[SecurityCheck]):
    for check in checks:
        check.execute()  # Works with any subclass
```

### I - Interface Segregation
```python
# MANY specific interfaces > ONE general interface

# BAD: One fat interface
class ISecurityService:
    def authenticate(): pass
    def authorize(): pass
    def encrypt(): pass
    def decrypt(): pass

# GOOD: Many specific interfaces
class IAuthenticator: def authenticate(): pass
class IAuthorizer: def authorize(): pass
class IEncryptor: 
    def encrypt(): pass
    def decrypt(): pass
```

### D - Dependency Inversion
```python
# DEPEND ON ABSTRACTIONS, NOT CONCRETIONS

# BAD: Depends on concrete class
class Scanner:
    def __init__(self):
        self.db = PostgreSQLDatabase()  # Hard dependency

# GOOD: Depends on abstraction
class ISQLDatabase: pass

class Scanner:
    def __init__(self, database: ISQLDatabase):
        self.db = database  # Injected, swappable
```

---

## Clean Code Quick Reference

### Naming
```python
# GOOD
vulnerability_severity = "CRITICAL"
def authenticate_user(credentials): pass
class SecurityPolicyEngine: pass

# BAD
x = "C"
def chk(p): pass
class Sec: pass
```

### Functions
```python
# Small! < 20-30 lines
# Few arguments! < 3 preferred
# Do ONE thing!

# GOOD
def validate_password(password: str) -> bool:
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    return True

# BAD
def validate_and_process_and_log_and_notify(data):
    # ... 100 lines doing many things
```

### Comments
```python
# GOOD: Explain WHY
# Using modified CVSS because asset valuations
# don't match standard weights
def calculate_risk(): pass

# BAD: Explain WHAT (code already shows)
def get_user():
    # Get user from database
    user = db.query("SELECT * FROM users")  # This is obvious
```

### Error Handling
```python
# Specific exceptions with context
class ScanTimeoutError(Exception):
    def __init__(self, target: str, timeout: int):
        message = f"Scan of {target} timed out after {timeout}s"
        super().__init__(message)
```

---

## Professional Ethics (The Clean Coder)

### The Oath
```
I will not be the cause of harm.
I will produce clean, tested code.
I will continuously improve my craft.
I will share my knowledge freely.
I will respect those before me.
I will help those who follow.
```

### Professional Responsibilities
1. First, do no harm
2. Obtain explicit authorization
3. Stay competent and current
4. Report honestly
5. Protect confidentiality

---

## Agile Security Practices

### Sprint Structure
- 2-week iterations
- Daily standups (15 min)
- Sprint review (demo working security)
- Sprint retrospective (continuous improvement)

### User Stories
```
As a [security stakeholder]
I want [security capability]
So that [business value]

Example:
As a security analyst
I want automatic vulnerability scanning
So that I can identify issues before attackers
```

### Test-Driven Security
```
RED:    Write failing test first
GREEN:  Write minimal code to pass
REFACTOR: Improve while keeping tests green
```

---

## Quality Metrics

| Metric | Target |
|--------|--------|
| Cyclomatic Complexity | < 10 |
| Lines per Function | < 30 |
| Test Coverage | > 80% |
| SOLID Compliance | 100% |
| Documentation | Code is self-documenting |

---

## Boy Scout Rule
> "Leave the code better than you found it."

Every interaction with code should:
- Apply SOLID principles
- Improve naming
- Extract long methods
- Remove duplication
- Add test coverage

---

## References

- Martin, R. C. (2017). *Clean Architecture*
- Martin, R. C. (2008). *Clean Code*
- Martin, R. C. (2011). *The Clean Coder*
- Martin, R. C. (2003). *Agile Software Development*

---

*Remember: Clean Architecture is not about structure, it's about making systems that can evolve over time without rewriting from scratch.*
