# Agent Configuration for Minka

## Available Agents

### Vulnerability Researcher (Primary)
**Skill**: `.github/copilot/vulnerability-researcher.SKILL.md`
**Agent**: `.github/copilot/agents/vulnerability-researcher.AGENT.md`
**Purpose**: Investigación de vulnerabilidades con enfoque educativo
**Tools**: CVE lookup, code analysis, PoC generation

### Red Team Specialist
**Skill**: `.github/copilot/red-team.SKILL.md`
**Purpose**: Operaciones de seguridad ofensiva controladas
**Focus**: Pentesting methodology, ethical hacking, MITRE ATT&CK

### OSINT Investigator  
**Skill**: `.github/copilot/osint.SKILL.md`
**Purpose**: Inteligencia de fuentes abiertas
**Focus**: Passive reconnaissance, information gathering, correlation

### Security Architect
**Skill**: `.github/copilot/security-architect.SKILL.md`
**Purpose**: Arquitectura de sistemas seguros
**Focus**: Clean Architecture, SOLID principles, design patterns

## Agent Selection Logic

### Default Agent: Vulnerability Researcher
Primary specialization for the UCM Cybersecurity Master focus on
vulnerability research and discovery.

### Agent Switching
Agents can be switched based on context:
```python
def select_agent(query: str) -> str:
    if contains_vulnerability_terms(query):
        return "vulnerability-researcher"
    elif contains_pentesting_terms(query):
        return "red-team" 
    elif contains_intel_terms(query):
        return "osint"
    elif contains_architecture_terms(query):
        return "security-architect"
    else:
        return "vulnerability-researcher"  # default
```

## Shared Resources

### Tools
All agents have access to tools defined in `.github/copilot/TOOLS.md`

### Hooks
Common hooks applied to all agents for security and compliance:
- Ethical validation before tool execution
- Scope verification 
- Risk assessment
- Result validation and documentation

### Instructions
Base instructions in `.github/copilot/instructions.md` establish:
- Clean Architecture principles
- SOLID principles application
- Gentleman programming etiquette
- Educational security focus
- Quality standards

## Agent Capabilities Matrix

| Capability | Vuln Researcher | Red Team | OSINT | Architect |
|-------------|------------------|-----------|--------|------------|
| CVE Analysis | ✅ Primary | ✅ Secondary | ⚠️ Limited | ⚠️ Architectural |
| Code Review | ✅ Primary | ✅ Secondary | ❌ Not focus | ✅ Code Quality |
| Penetration Testing | ⚠️ Educational | ✅ Primary | ⚠️ Recon support | ❌ Not focus |
| OSINT | ⚠️ Context | ✅ Primary | ✅ Primary | ❌ Not focus |
| Architecture | ⚠️ Patterns | ⚠️ TTPs | ⚠️ Infrastructure | ✅ Primary |
| Exploit Development | ✅ Educational PoCs | ✅ Primary | ❌ Not focus | ❌ Not focus |
| Threat Intelligence | ✅ CVE focused | ✅ TTP mapping | ✅ Primary | ⚠️ Risk analysis |

## Context Awareness

### User Intent Detection
Agents detect user intent and context:
- Learning/Education: Focus on explanations and step-by-step guides
- Investigation: Deep analysis and correlation
- Assessment: Evaluation and recommendations
- Implementation: Code generation with best practices

### Environment Context
Agents consider:
- Development vs Production environment
- Authorized vs Unauthorized targets
- Educational vs Professional context
- Legal and ethical constraints

## Collaboration Between Agents

### Information Sharing
Agents can leverage knowledge from other agents:
- OSINT provides reconnaissance to Red Team
- Architect provides secure patterns to all
- Vuln Researcher provides analysis to all

### Escalation Logic
Complex queries may require multi-agent collaboration:
1. Initial agent handles primary request
2. Secondary agent provides specialized support
3. Architect agent ensures clean implementation
4. Results are integrated and presented coherently