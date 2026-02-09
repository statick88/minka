"""
Minka Narrative Generator - Generador de Narrativas Estilo Mitnick

Genera explicaciones narrativas para conceptos de ciberseguridad.
"""

import random
from typing import Dict, Any

# ============================================
# PLANTILLAS NARRATIVAS
# ============================================

NARRATIVE_TEMPLATES = {
    "sql_injection": {
        "hook": "Imagina que le dices a un mesero: 'Deme el menú Y después tire toda la cocina.'",
        "context": "SQL Injection está en el OWASP Top 10 desde hace más de una década.",
        "story": """
En 2017, un atacante usó SQL Injection para extraer 145 millones de registros
de una base de datos corporativa. No escribió código complejo.
Solo sabía hablarle a la base de datos en su idioma.
        """,
        "technique": """
El atacante usa comillas para escapar de la consulta original:
```sql
' OR '1'='1
```
Esto transforma la query benigna en algo completamente diferente.
        """,
        "lesson": """
La defensa? Paredes parametrizadas.
Como pedirle al mesero que solo entregue lo que está en el menú, nada más.
        """,
        "prevention": [
            "Usar consultas parametrizadas (Prepared Statements)",
            "ORMs como SQLAlchemy o Hibernate",
            "Input validation y sanitization",
            "Principio de mínimo privilegio",
        ],
    },
    "xss": {
        "hook": "Tu website confía en todo lo que el usuario escribe. El usuario no.",
        "context": "Cross-Site Scripting (XSS) permite inyectar scripts maliciosos en páginas web.",
        "story": """
Un atacante descubre que un foro no sanea los comentarios.
Escribe: <script>robar_cookies()</script>
Ahora, cada vez que alguien visita la página, sus cookies se envían al atacante.
Sesiones comprometidas. Cuentas robadas.
Todo con 40 caracteres de código.
        """,
        "technique": """
Tipos de XSS:
1. Stored XSS: El script se guarda en la base de datos
2. Reflected XSS: El script viene en la URL
3. DOM-based XSS: Manipulación del DOM en el cliente
        """,
        "lesson": """
La regla de oro: Nunca confíes en el input del usuario.
NUNCA.
        """,
        "prevention": [
            "Content Security Policy (CSP)",
            "Escape de caracteres especiales",
            "Input validation",
            "HTTPOnly y Secure flags en cookies",
        ],
    },
    "csrf": {
        "hook": "Tu banco confía en tu navegador. El atacante abusa de esa confianza.",
        "context": "Cross-Site Request Forgery obliga al navegador a enviar requests no autorizados.",
        "story": """
El atacante crea una página con una imagen invisible:
<img src="https://bank.com/transfer?to=atacante&amount=10000">

Cuando la víctima visita la página, el navegador automáticamente
hace el request al banco. Con las cookies de sesión.
El banco dice: "Sí, request válido."
El dinero se ha ido.
        """,
        "technique": """
El navegador incluye automáticamente las cookies.
El servidor no puede distinguir entre un request legítimo y uno forzado.
Por eso se llama "Cross-Site".
        """,
        "lesson": """
Anti-CSRF tokens al rescate.
Cada form incluye un token único.
El servidor verifica que el token coincida.
        """,
        "prevention": [
            "Anti-CSRF tokens",
            "SameSite cookies",
            "Referer header validation",
            "CAPTCHA para acciones sensibles",
        ],
    },
    "authentication_bypass": {
        "hook": "A veces, la puerta no está cerrada. Solo parece que lo está.",
        "context": "Los mecanismos de autenticación pueden fallar de formas inesperadas.",
        "story": """
Un atacante nota que el login tiene dos parámetros:
username=admin&password=incorrect

Y si modifica la request?
username=admin&password[$ne]=wrong

MongoDB interpreta $ne como "no igual".
Password no es igual a "wrong". True.
Acceso concedido.
        """,
        "technique": """
La aplicación confiaba en el parser de JSON/queries.
No validaba los operadores de MongoDB.
Un error común cuando los devs mezclan input del usuario con queries.
        """,
        "lesson": """
Separar always: datos de código.
Los operadores de base de datos nunca deben venir del usuario.
        """,
        "prevention": [
            "Parameterized queries",
            "Whitelist validation",
            "Segregación de datos y código",
            "Code review especializado",
        ],
    },
    "rce": {
        "hook": "Cuando tu código se ejecuta en el servidor del atacante... ya es demasiado tarde.",
        "context": "Remote Code Execution permite ejecutar comandos arbitrarios en el servidor.",
        "story": """
Una aplicación web permitía subir avatares.
El código verificaba la extensión... solo la extensión.
avatar.php.jpg passes!
El servidor ejecutaba el archivo como PHP.
Un simple web shell después.
Acceso total al servidor.
        """,
        "technique": """
Pasos típicos:
1. Encontrar vector de input (upload, params, headers)
2. Bypassear controles
3. Subir/Crear archivo malicioso
4. Ejecutar
        """,
        "lesson": """
Never trust user input.
Ni el filename. Ni el content-type. Ni nada.
Valida todo. Sana input. whitelist everything.
        """,
        "prevention": [
            "Input validation (whitelist)",
            "File upload restrictions",
            "Sandboxing",
            "Principio de mínimo privilegio",
        ],
    },
    "privilege_escalation": {
        "hook": "root es solo otro usuario. Solo hay que saber cómo llegar a él.",
        "context": "Elevar privilegios de usuario limitado a administrador.",
        "story": """
Un atacante tiene acceso a un servidor web.
Solo puede leer archivos del directorio /var/www.
Encuentra un binario con permisos setuid.
 ejecuta arbitrary code como root.
gcc /tmp/exploit.c -o /tmp/exploit
/tmp/exploit
# whoami
root
        """,
        "technique": """
Tipos de escalada:
1. Local: Ya tienes accesso, quieres más
2. Vertical: De usuario a admin
3. Horizontal: De tu usuario a otro usuario
        """,
        "lesson": """
Hardening, patching, y least privilege.
Minimiza la superficie de ataque.
        """,
        "prevention": [
            "Patch management",
            "Setuid/Ssetgid audit",
            "Container isolation",
            "Least privilege principle",
        ],
    },
}

# ============================================
# GENERADOR DE NARRATIVAS
# ============================================


async def generate_narrative(
    concept: str, audience: str = "intermediate", format: str = "mixed"
) -> str:
    """Genera una narrativa para un concepto de ciberseguridad."""

    concept_lower = concept.lower()

    # Buscar concepto
    for key, narrative in NARRATIVE_TEMPLATES.items():
        if concept_lower in key or concept_lower in narrative.get("hook", "").lower():
            return format_narrative(narrative, audience, format)

    # Si no encuentra, generar narrativa genérica
    return generate_generic_narrative(concept, audience, format)


def format_narrative(narrative: Dict[str, Any], audience: str, format: str) -> str:
    """Formatea una narrativa según el nivel y formato."""

    if format == "story":
        return f"""> {narrative["hook"]}

{narrative["story"]}
"""

    elif format == "technical":
        lines = [
            f"## {list(NARRATIVE_TEMPLATES.keys())[list(NARRATIVE_TEMPLATES.values()).index(narrative)].upper()}",
            "",
            "### Contexto",
            narrative["context"],
            "",
            "### La Técnica",
            narrative["technique"],
            "",
            "### Prevención",
            "\n".join(f"- {p}" for p in narrative["prevention"]),
        ]
        return "\n".join(lines)

    else:  # mixed - formato completo estilo Mitnick
        topic_name = list(NARRATIVE_TEMPLATES.keys())[
            list(NARRATIVE_TEMPLATES.values()).index(narrative)
        ]

        return f"""> 🎭 **{narrative["hook"]}**

## {topic_name.upper().replace("_", " ")}

{narrative["context"]}

---

### 💬 La Historia

{narrative["story"]}

---

### ⚙️ La Técnica

{narrative["technique"]}

---

### 🎓 La Lección

> *{narrative["lesson"]}*

---

### 🛡️ Prevención

{narrative["lesson"]}

**Medidas concretas:**
{"".join(f"- **{p}**\n" for p in narrative["prevention"])}

---

> *"¿Sabes qué hace esto tan fascinante? Que con 40 caracteres puedes comprometer un sistema entero."*
"""


def generate_generic_narrative(concept: str, audience: str, format: str) -> str:
    """Genera una narrativa genérica cuando no se encuentra el concepto."""
    import random

    opening = random.choice(OPENING_QUOTES)

    return f"""> *{opening}*

**{concept}** es uno de esos temas que parece simple... hasta que no lo es.

### Contexto

En el mundo de la ciberseguridad, cada técnica tiene su historia.
Y cada historia tiene una lección.

### ¿Qué pasaría si...?

Imagina que un atacante descubre cómo explotar {concept}.
Primero, necesita entender cómo funciona el sistema.
Luego, encuentra la grieta.
Finalmente, la amplía.

### La Técnica

Pero aquí está lo bueno: defenders pueden anticipar estos ataques.
Con las técnicas correctas, puedes construir sistemas resilientes.

### Prevención

- **Entiende el ataque** antes de defender
- **Patch management** es tu mejor amigo
- **Defense in depth** - múltiples capas
- **Least privilege** - mínimo acceso necesario

### Tu Turno

Ahora tú: ¿qué pasaría si {concept} se usara en tu sistema?

---

> *"La curiosidad es mi superpower. La seguridad es mi pasión."*
"""


# ============================================
# CITAS ALEATORIAS PARA INCORPORAR
# ============================================

OPENING_QUOTES = [
    "¿Sabes qué hace esto tan fascinante?",
    "La belleza está en...",
    "Y aquí viene lo bueno...",
    "El truco aquí es...",
    "¿Qué pasaría si...?",
    "Imagina el momento exacto cuando...",
    "Esto es lo que hace que la seguridad sea tan... interesante.",
]

CLOSING_QUOTES = [
    "La seguridad es un proceso, no un producto.",
    "Piensa como un atacante para defender mejor.",
    "El eslabón más débil suele ser el humano.",
    "Always leave the code better than you found it.",
    "Functions should do one thing. They should do it well.",
]


async def get_narrative_wrapper(concept: str, audience: str = "intermediate") -> str:
    """Obtiene una narrativa completa con cita de apertura."""

    opening = random.choice(OPENING_QUOTES)
    narrative = await generate_narrative(concept, audience, "mixed")

    # Insertar cita de apertura
    narrative = narrative.replace('> *"¿Sabes qué hace esto tan fascinante?"*', f'> *"{opening}"*')

    return narrative
