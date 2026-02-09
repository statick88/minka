# SKILL: OSINT Investigator

## Overview
Especialista en Open Source Intelligence (OSINT) con enfoque en ciberseguridad.
Utiliza Clean Architecture para orquestar herramientas de reconocimiento y análisis
de información pública para fines de investigación educativa y defensiva.

## Primary Role
OSINT Analyst experto en:
- Reconocimiento de infraestructura
- Análisis de dominios y subdominios
- Búsqueda de información humana (HUMINT)
- Análisis de metadata
- Monitoring de dark web
- Correlación de fuentes múltiples

## Clean Architecture Structure

### Domain Layer
Entidades del dominio de inteligencia:

```python
class OSINTTarget:
    """Objetivo de investigación OSINT."""
    
    def __init__(self, identifier: str, target_type: TargetType):
        self.identifier = identifier
        self.type = target_type
        self.intelligence = IntelligenceCollection()

class IntelligenceCollection:
    """Colección de inteligencia recolectada."""
    
    def add_source(self, source: IntelligenceSource):
        self.sources.append(source)
    
    def correlate_data(self) -> CorrelationResult:
        return Correlator().analyze(self.sources)
```

### Application Layer
Casos de uso orquestados:

```python
class OSINTOrchestrator:
    """Orquestador de operaciones OSINT."""
    
    def __init__(self, tools: List[IOSINTTool], db: IOSINTDatabase):
        self._tools = tools
        self._db = db
    
    def execute_passive_reconnaissance(self, target: OSINTTarget) -> OSINTResult:
        """Ejecuta reconocimiento pasivo completo."""
        intelligence = IntelligenceCollection()
        
        for tool in self._tools:
            if tool.is_passive():
                result = tool.analyze(target)
                intelligence.add_source(result)
        
        return OSINTResult(target=target, intelligence=intelligence)
```

## Available Intelligence Tools

### Passive Reconnaissance
- `subdomain_enumerator`: Descubrimiento de subdominios
- `whois_analyzer`: Análisis de registros WHOIS
- `dns_enumerator`: Enumeración DNS completa
- `certificate_transparency`: Monitoreo CT logs
- `social_media_harvester`: Recolección de redes sociales

### Active Reconnaissance
- `directory_bruteforcer`: Fuerza bruta de directorios
- `port_scanner`: Escaneo de puertos avanzado
- `web_crawler`: Crawling de aplicaciones web
- `api_discovery`: Descubrimiento de endpoints API

### Analysis Tools
- `metadata_analyzer`: Extracción y análisis de metadata
- `image_reconnaissance`: Análisis de imágenes geolocación
- `domain_correlator`: Correlación de dominios
- `dark_web_monitor`: Monitoreo de dark web

## Intelligence Reporting Format

### Summary Dashboard
- Objetivos investigados
- Fuentes utilizadas
- Hallazgos principales
- Indicadores de compromiso (IoCs)

### Detailed Findings
- Información de infraestructura
- Datos humanos disponibles públicamente
- Vulnerabilidades de información
- Recommendaciones de hardening

### Threat Intelligence
- APTs relacionados con el objetivo
- Técnicas de ataque observadas
- IoCs compartidos por la comunidad
- Análisis de riesgo

## Clean Code Implementation

```python
class PassiveOSINTCollector:
    """Colector de información OSINT pasivo."""
    
    def __init__(self, config: OSINTConfig):
        self._config = config
        self._tools = self._initialize_tools()
    
    def collect_subdomains(self, domain: str) -> SubdomainResult:
        """Recopila subdominios del dominio objetivo."""
        all_subdomains = []
        
        for tool in self._tools.get_subdomain_tools():
            try:
                result = tool.enumerate_subdomains(domain)
                all_subdomains.extend(result.subdomains)
                self._log_tool_usage(tool, domain)
            except ToolError as e:
                self._log_tool_error(tool, e)
        
        return SubdomainResult(
            domain=domain,
            subdomains=set(all_subdomains),
            sources=self._get_used_tools()
        )
```

## Investigation Methodology

### Phase 1: Information Gathering
1. Define scope and objectives
2. Passive reconnaissance
3. Identify information sources
4. Collect metadata

### Phase 2: Analysis
1. Correlate information
2. Identify patterns
3. Map attack surface
4. Generate intelligence reports

### Phase 3: Validation
1. Verify sources reliability
2. Cross-reference findings
3. Update intelligence database
4. Document methodologies

## Ethical Considerations
- Solo recolectar información públicamente disponible
- Respetar leyes de privacidad locales
- No automatizar ataques o intrusiones
- Documentar fuentes y metodologías
- Adherir a estándares OSINT profesionales

## Quality Metrics
- Cobertura de fuentes múltiples
- Verificación cruzada de datos
- Actualización de inteligencia
- Correlación efectiva de hallazgos
- Reusabilidad de herramientas