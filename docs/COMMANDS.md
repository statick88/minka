# Minka MCP Tools Reference

## Available Tools

### 1. `minka-experts`
Search and cite security researchers and institutions.

**Usage:**
```json
{
  "query": "Carlini",
  "format": "brief|detailed|citation"
}
```

**Examples:**
- `"Carlini"` - Brief info about Nicholas Carlini
- `"Dawn Song"` - UC Berkeley professor
- `"NIST"` - Research institutions

---

### 2. `minka-ai-security`
Search AI security papers and research.

**Usage:**
```json
{
  "query": "adversarial",
  "year": 2024
}
```

**Examples:**
- `"adversarial examples"`
- `"prompt injection"`
- `"ember 2024"`

---

### 3. `minka-cases`
Get case studies of real security incidents.

**Usage:**
```json
{
  "case": "SolarWinds"
}
```

**Examples:**
- `"Stuxnet"`
- `"Equifax"`
- `"Target Breach"`
- `"Colonial Pipeline"`

---

### 4. `minka-quote`
Get a quote in Mitnick's storytelling style.

**Usage:**
```json
{
  "type": "mitnick|uncle_bob"
}
```

---

### 5. `minka-narrative`
Generate a narrative for a security concept.

**Usage:**
```json
{
  "concept": "SQL injection",
  "audience": "beginner|intermediate|advanced",
  "format": "story|technical|mixed"
}
```

**Examples:**
- `"XSS"`
- `"CSRF"`
- `"RCE"`
- `"Buffer Overflow"`

---

### 6. `minka-vuln`
Get CVE information and vulnerability details.

**Usage:**
```json
{
  "cve": "CVE-2021-44228"
}
```

**Examples:**
- `"Log4Shell"`
- `"Heartbleed"`
- `"EternalBlue"`

---

### 7. `minka-ucm`
Get UCM Master curriculum module information.

**Usage:**
```json
{
  "module": "Red Team"
}
```

**Examples:**
- `"Blue Team"`
- `"DFIR"`
- `"Cryptography"`
- `"Web Security"`

---

### 8. `minka-cleanarch`
Get Clean Architecture and Uncle Bob principles.

**Usage:**
```json
{
  "topic": "SOLID",
  "principle": "SRP"
}
```

**Examples:**
- `"Clean Code"`
- `"Clean Architecture"`
- `"SOLID"`
- `"Dependency Inversion"`

---

## Quick Reference

| Tool | Query | Format |
|------|-------|--------|
| `minka-experts` | Researcher name | brief/detailed/citation |
| `minka-ai-security` | Paper topic | - |
| `minka-cases` | Case name | - |
| `minka-quote` | Type (mitnick/uncle_bob) | - |
| `minka-narrative` | Concept | story/technical/mixed |
| `minka-vuln` | CVE ID or name | - |
| `minka-ucm` | Module name | - |
| `minka-cleanarch` | Topic/principle | - |
