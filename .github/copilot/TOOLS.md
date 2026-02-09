# TOOLS

## Security Analysis Tools

### nmap_scan
**Description**: Realiza escaneos de red y puertos utilizando nmap
**Parameters**:
- `target` (string): IP o hostname a escanear
- `ports` (string, optional): Rango o lista de puertos
- `scan_type` (string): Tipo de escaneo (quick, comprehensive, stealth)

### code_vulnerability_scan
**Description**: Analiza código fuente en busca de patrones de vulnerabilidades
**Parameters**:
- `code` (string): Código fuente a analizar
- `language` (string): Lenguaje de programación (python, javascript, java, c)
- `depth` (string): Nivel de análisis (basic, deep)

### cve_lookup
**Description**: Busca información detallada sobre CVEs específicos
**Parameters**:
- `cve_id` (string): Identificador CVE (ej: CVE-2021-44228)
- `include_references` (boolean): Incluir referencias y fuentes

### generate_poc
**Description**: Genera Proof of Concept educativo para vulnerabilidades
**Parameters**:
- `vulnerability_type` (string): Tipo de vulnerabilidad (sqli, xss, buffer_overflow, rce)
- `language` (string): Lenguaje para el PoC (python, c, java, javascript)
- `educational_notes` (boolean): Incluir notas educativas detalladas

### security_headers_check
**Description**: Verifica cabeceras de seguridad HTTP
**Parameters**:
- `url` (string): URL a analizar
- `detailed_analysis` (boolean): Análisis detallado de configuración

### dependency_vulnerability_scan
**Description**: Escanea dependencias en busca de vulnerabilidades conocidas
**Parameters**:
- `manifest_path` (string): Ruta a archivo de dependencias (package.json, requirements.txt)
- `severity_filter` (string): Filtrar por severidad (critical, high, medium, low)

## Intelligence Gathering Tools

### osint_domain_reconnaissance
**Description**: Realiza reconocimiento OSINT de dominios
**Parameters**:
- `domain` (string): Dominio objetivo
- `passive_only` (boolean): Solo técnicas pasivas
- `depth` (string): Profundidad del análisis (basic, comprehensive)

### subdomain_enumeration
**Description**: Enumera subdominios utilizando múltiples técnicas
**Parameters**:
- `domain` (string): Dominio principal
- `techniques` (array): Técnicas a usar (dns_brute, certificate_transparency, search_engines)
- `wordlist_path` (string): Ruta a wordlist personalizada

## Response Format

### Success Response
```json
{
  "status": "success",
  "tool": "nmap_scan",
  "result": {
    "open_ports": [80, 443, 8080],
    "services": ["http", "https-alt", "http-proxy"],
    "version_info": {...}
  },
  "metadata": {
    "execution_time": "2.3s",
    "confidence": "high"
  }
}
```

### Error Response
```json
{
  "status": "error", 
  "tool": "nmap_scan",
  "error": "Target unreachable",
  "details": "Connection timeout to 192.168.1.1"
}
```