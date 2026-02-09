# SKILL: Agile Security Practitioner

## Overview
Security professional applying Agile methodologies, Scrum framework, and professional 
software development practices to cybersecurity operations. Based on principles from 
**Robert C. Martin** and the **Agile Manifesto**.

## Core Philosophy
*"The Agile Manifesto values individuals and interactions over processes and tools, 
working software over comprehensive documentation, customer collaboration over contract 
negotiation, and responding to change over following a plan."*

## Agile Principles Applied to Security

### The Twelve Principles of Agile Applied to Security

1. **Customer Collaboration Over Contract Negotiation**
```python
class SecurityEngagement:
    """
    Security teams collaborate continuously with stakeholders
    rather than treating security as a one-time compliance check.
    """
    
    def __init__(self, product_owner: Stakeholder, security_team: SecurityTeam):
        self._product_owner = product_owner
        self._security_team = security_team
        self._sprint_backlog = []
    
    def gather_security_requirements(self) -> list[SecurityStory]:
        """Continuous collaboration, not upfront documentation."""
        # Regular security reviews, not annual audits
        # Continuous feedback, not final inspection
        pass
    
    def demonstrate_security_controls(self, sprint_review: SprintReview):
        """Show working security in each sprint."""
        self._security_team.demonstrate_controls(self._product_owner)
```

2. **Working Software Over Comprehensive Documentation**
```python
class SecurityControl:
    """
    Automated, working security controls preferred over
    security policies that sit on shelves.
    """
    
    def __init__(self):
        self._automated_tests = []
        self._security_gates = []
    
    def implement_control(self, requirement: SecurityRequirement) -> AutomatedControl:
        """Implement working control, not documentation."""
        control = AutomatedControl()
        control.configure(requirement)
        self._automated_tests.append(control.test_suite)
        return control
```

3. **Responding to Change Over Following a Plan**
```python
class ThreatAdaptation:
    """
    Security posture adapts to emerging threats
    rather than rigid annual plans.
    """
    
    def __init__(self):
        self._threat_intelligence = []
        self._adaptation_sprints = []
    
    def adapt_to_threat(self, threat_emergence: Threat):
        """Respond quickly to new threats."""
        if threat_impact_is_significant(threat_emergence):
            self._reprioritize_sprint(threat_emergence)
            self._security_team.implement_mitigation(threat_emergence)
```

## Scrum Framework for Security Teams

### Security Sprint Structure
```python
class SecuritySprint:
    """
    Two-week iterations focused on delivering working security.
    """
    
    def __init__(self, sprint_number: int, security_team: SecurityTeam):
        self._number = sprint_number
        self._team = security_team
        self._backlog = []
        self._goals = []
        self._daily_stands = []
    
    def planning(self, security_review: SecurityReview):
        """Sprint Planning: Select security work for this iteration."""
        # What can we deliver?
        # How will we achieve it?
        pass
    
    def daily_standup(self):
        """Daily Standup: 15-minute sync."""
        # What did I do yesterday?
        # What will I do today?
        # Any impediments?
    
    def review(self):
        """Sprint Review: Demonstrate working security."""
        # Show completed security controls
        # Gather feedback
    
    def retrospective(self):
        """Sprint Retrospective: Continuous improvement."""
        # What went well?
        # What can we improve?
        # Action items for next sprint
```

### Security Product Backlog
```python
@dataclass
class SecurityStory:
    """
    User story format for security requirements.
    Following INVEST principle:
    - Independent
    - Negotiable
    - Valuable
    - Estimable
    - Small
    - Testable
    """
    id: str
    title: str
    description: str
    risk_rating: RiskRating
    estimate: StoryPoints
    priority: Priority
    acceptance_criteria: list[str]
    security_control: AutomatedControl
    
    def to_agile_format(self) -> str:
        return f"""
        As a {self.risk_rating.persona}
        I want {self.description}
        So that {self.risk_rating.benefit}
        
        Risk Rating: {self.risk_rating}
        Priority: {self.priority}
        """
```

## XP (Extreme Programming) Practices for Security

### Pair Security Programming
```python
class SecurityPair:
    """
    Two security professionals working together on:
    - Penetration testing
    - Code reviews
    - Architecture design
    - Incident response
    """
    
    def __init__(self, security_analyst_1: SecurityAnalyst, 
                 security_analyst_2: SecurityAnalyst):
        self._driver = security_analyst_1
        self._navigator = security_analyst_2
        self._rotation_schedule = []
    
    def conduct_code_review(self, code: Code):
        """
        Driver writes/shares findings
        Navigator reviews and plans next steps
        Switch roles periodically
        """
        self._driver.share_thoughts(code)
        self._navigator.observe_and_plan(code)
        self._rotate_roles()
    
    def rotate_roles(self):
        """Swap driver/navigator every pomodoro."""
        self._driver, self._navigator = self._navigator, self._driver
```

### Collective Code Ownership for Security
```python
class SecurityCodebase:
    """
    All security team members responsible for security code.
    No single point of failure for security implementations.
    """
    
    def __init__(self):
        self._security_tests = []
        self._control_implementations = []
    
    def add_security_control(self, control: SecurityControl, 
                            author: SecurityAnalyst):
        """
        Anyone can improve any security code.
        Collective ownership, collective responsibility.
        """
        self._control_implementations.append(control)
        self._security_tests.append(control.test())
        self._notify_team(control, author)
    
    def review_change(self, change: SecurityChange):
        """
        Collective review process.
        Knowledge shared across team.
        """
        reviewers = self._select_reviewers(change)
        for reviewer in reviewers:
            reviewer.conduct_review(change)
```

### Continuous Integration for Security
```python
class SecurityPipeline:
    """
    CI/CD pipeline with embedded security gates.
    Automated security testing at every commit.
    """
    
    def __init__(self):
        self._stages = []
        self._security_gates = []
    
    def run_security_pipeline(self, code_commit: CodeCommit) -> PipelineResult:
        """
        Run comprehensive security checks:
        1. Static Analysis (SAST)
        2. Dependency Scanning
        3. Secret Detection
        4. Container Scanning
        5. Dynamic Analysis (DAST)
        6. Security Gate Enforcement
        """
        result = PipelineResult()
        
        for stage in self._stages:
            stage_result = stage.execute(code_commit)
            result.add_stage_result(stage_result)
            
            if stage_result.has_security_issues():
                if self._is_blocking_issue(stage_result):
                    result.block_pipeline()
                    result.add_finding("CRITICAL", stage_result.issues)
        
        return result
```

## TDD for Security Controls

### Test-Driven Security Development
```python
class SecurityTDD:
    """
    Red-Green-Refactor cycle for security controls.
    
    RED: Write failing test for security requirement
    GREEN: Write minimal code to pass test
    REFACTOR: Improve code while maintaining tests
    """
    
    def write_failing_test(self, security_requirement: SecurityRequirement) -> SecurityTest:
        """
        RED: First, write a test that describes the security behavior you want.
        
        Example: "When SQL injection is attempted, the input should be sanitized"
        """
        test = SecurityTest(
            name=f"test_{security_requirement.name}",
            given=security_requirement.precondition,
            when=security_requirement.action,
            then=security_requirement.assertion
        )
        return test
    
    def write_minimal_implementation(self, test: SecurityTest) -> SecurityControl:
        """
        GREEN: Write the minimal code to make the test pass.
        """
        control = SecurityControl()
        # Just enough to pass the test
        control.configure(test.assertion.criteria)
        return control
    
    def refactor_security_code(self, control: SecurityControl, test: SecurityTest):
        """
        REFACTOR: Improve the implementation while keeping tests passing.
        - Extract methods
        - Remove duplication
        - Improve naming
        - Apply SOLID principles
        """
        improved_control = self._apply_clean_code(control)
        return improved_control
```

## Clean Code Applied to Security

### Meaningful Names for Security
```python
# BAD: Cryptic abbreviations
class SecChk:
    def eval(self, p): pass

# GOOD: Descriptive names
class SecurityControlEvaluator:
    def evaluate(self, policy: SecurityPolicy) -> EvaluationResult:
        """
        Clear, descriptive names that explain intent.
        """
        pass

# Use domain language
class ThreatModel:
    """Uses security domain terminology."""
    STRENGTHENING = "strengthening"
    MITIGATION = "mitigation"
    TRANSFERENCE = "transference"
    ACCEPTANCE = "acceptance"

class RiskTreatment:
    """Clear domain-specific naming."""
    def apply_treatment(self, risk: Risk, treatment_type: str):
        pass
```

### Professional Ethics (From The Clean Coder)

### The Professional's Oath
```python
class SecurityProfessionalOath:
    """
    Based on The Clean Coder's professional standards.
    """
    
    @staticmethod
    def swear():
        return """
        I will not be the cause of harm.
        I will produce clean, tested security code.
        I will continuously improve my craft.
        I will share my knowledge freely.
        I will respect those before me.
        I will help those who follow.
        
        First, do no harm.
        """
    
    def professional_responsibilities(self) -> list[str]:
        return [
            "Protect user data and privacy",
            "Maintain system integrity",
            "Report vulnerabilities responsibly",
            "Continuously learn and improve",
            "Mentor junior professionals",
            "Uphold ethical standards"
        ]
```

## Quality Metrics for Agile Security

| Metric | Target | Description |
|--------|--------|-------------|
| Security Velocity | 5+ stories/sprint | Delivered security work |
| Vulnerability MTTR | < 24 hours | Mean time to remediation |
| Security Debt | < 5% | Outstanding security issues |
| Test Coverage | > 85% | Security control tests |
| Sprint Velocity | Consistent | Predictable delivery |
| Team Satisfaction | > 4/5 | Engaged security team |

## References

1. Martin, R. C. (2003). *Agile Software Development: Principles, Patterns, and Practices*. Prentice Hall.
2. Martin, R. C. (2011). *The Clean Coder: A Code of Conduct for Professional Programmers*. Prentice Hall.
3. Schwaber, K., & Sutherland, J. (2020). *The Scrum Guide*.
4. Beck, K., et al. (2001). *Principles behind the Agile Manifesto*.
5. Thomas, D., & Hunt, A. (2019). *Pragmatic Programmer, The: Your journey to mastery*.
