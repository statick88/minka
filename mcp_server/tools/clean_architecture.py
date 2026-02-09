"""
Minka Clean Architecture - Principios de Robert C. Martin

Clean Code, Clean Architecture, SOLID, y Clean Agile.
"""

# ============================================
# PRINCIPIOS SOLID
# ============================================

SOLID_PRINCIPLES = {
    "SRP": {
        "name": "Single Responsibility Principle",
        "acronym": "SRP",
        "principle": "A class should have only one reason to change.",
        "description": """
Cada clase debe tener UNA sola responsabilidad.
No debe haber más de un motivo para cambiar una clase.
        """,
        "example": """
**MAL:**
```python
class User:
    def authenticate(self): pass  # Autenticación
    def send_email(self): pass      # Envío de emails
    def calculate_discount(self): pass  # Lógica de negocio
```

**BIEN:**
```python
class User:
    def authenticate(self): pass

class EmailService:
    def send_email(self): pass

class DiscountCalculator:
    def calculate_discount(self, user, product): pass
```""",
        "benefits": [
            "Código más fácil de entender",
            "Código más fácil de mantener",
            "Menor acoplamiento",
            "Mayor cohesión",
        ],
    },
    "OCP": {
        "name": "Open/Closed Principle",
        "acronym": "OCP",
        "principle": "Software entities should be open for extension but closed for modification.",
        "description": """
Las entidades de software deben estar ABIERTAS para extensión,
pero CERRADAS para modificación.

Debes poder añadir funcionalidad SIN modificar código existente.
        """,
        "example": """
**MAL:**
```python
class ReportGenerator:
    def generate(self, type):
        if type == "PDF":
            # generar PDF
        elif type == "Excel":
            # generar Excel
```

**BIEN:**
```python
from abc import ABC, abstractmethod

class ReportGenerator(ABC):
    @abstractmethod
    def generate(self): pass

class PDFReportGenerator(ReportGenerator):
    def generate(self): pass

class ExcelReportGenerator(ReportGenerator):
    def generate(self): pass
```""",
        "benefits": [
            "Extensibilidad sin modificar código existente",
            "Reducción de riesgo al añadir features",
            "Código más estable",
        ],
    },
    "LSP": {
        "name": "Liskov Substitution Principle",
        "acronym": "LSP",
        "principle": "Objects of a superclass should be replaceable with objects of a subclass without affecting correctness.",
        "description": """
Si una clase S hereda de una clase B,
debes poder usar S en cualquier lugar donde uses B,
sin que el programa deje de funcionar.
        """,
        "example": """
**MAL:**
```python
class Bird:
    def fly(self): pass

class Penguin(Bird):
    def fly(self):
        raise Exception("Penguins can't fly!")
```

**BIEN:**
```python
class Bird: pass

class FlyingBird(Bird):
    def fly(self): pass

class NonFlyingBird(Bird):
    def swim(self): pass

class Penguin(NonFlyingBird):
    def swim(self): pass
```""",
        "benefits": ["Polimorfismo seguro", "Código más predecible", "Tests más simples"],
    },
    "ISP": {
        "name": "Interface Segregation Principle",
        "acronym": "ISP",
        "principle": "Clients should not be forced to depend on methods they do not use.",
        "description": """
Es mejor tener muchas interfaces específicas
que una interfaz general.

Los clientes no deberían verse obligados a implementar
métodos que no utilizan.
        """,
        "example": """
**MAL:**
```python
class Machine(ABC):
    @abstractmethod
    def print(self, document): pass
    @abstractmethod
    def scan(self, document): pass
    @abstractmethod
    def fax(self, document): pass

class OldPrinter(Machine):
    def print(self, document): pass
    def scan(self, document):
        raise Exception("No scan capability")
```

**BIEN:**
```python
class Printer(ABC):
    @abstractmethod
    def print(self, document): pass

class Scanner(ABC):
    @abstractmethod
    def scan(self, document): pass

class OldPrinter(Printer):
    def print(self, document): pass
```""",
        "benefits": [
            "Interfaces más pequeñas y focused",
            "Mayor flexibilidad",
            "Código más fácil de implementar",
        ],
    },
    "DIP": {
        "name": "Dependency Inversion Principle",
        "acronym": "DIP",
        "principle": """
1. High-level modules should not depend on low-level modules. Both should depend on abstractions.
2. Abstractions should not depend on details. Details should depend on abstractions.
        """,
        "description": """
Los módulos de alto nivel NO deben depender de módulos de bajo nivel.
Ambos deben depender de ABSTRACCIONES.

Esto se logra mediante Dependency Injection.
        """,
        "example": """
**MAL:**
```python
class MySQLDatabase:
    def connect(self): pass
    def query(self, sql): pass

class UserRepository:
    def __init__(self):
        self.db = MySQLDatabase()  # Dependencia concreta!
```

**BIEN:**
```python
from abc import ABC
from typing import Protocol

class Database(ABC):
    @abstractmethod
    def connect(self): pass
    @abstractmethod
    def query(self, sql): pass

class MySQLDatabase(Database):
    def connect(self): pass
    def query(self, sql): pass

class PostgreSQLDatabase(Database):
    def connect(self): pass
    def query(self, sql): pass

class UserRepository:
    def __init__(self, db: Database):  # Dependency Injection
        self.db = db
```""",
        "benefits": [
            "Código desacoplado",
            "Fácil de testear (mocks)",
            "Flexibilidad para cambiar implementaciones",
        ],
    },
}

# ============================================
# CLEAN CODE PRINCIPLES
# ============================================

CLEAN_CODE_PRINCIPLES = {
    "naming": {
        "principle": "Meaningful Names",
        "rules": [
            "Usar nombres que revelen intención",
            "Evitar nombres confusos (a, b, c)",
            "Usar nombres pronunciables",
            "Usar nombres buscables",
            "Una variable por concepto",
        ],
        "example": """
**MAL:**
```python
d = 12  # qué es esto?
el = datetime.now().day
lst = get_users()
```

**BIEN:**
```python
days_since_last_login = 12
current_day = datetime.now().day
user_list = get_users()
```""",
    },
    "functions": {
        "principle": "Small Functions",
        "rules": [
            "Las funciones deben hacer UNA cosa",
            "Idealmente menos de 20 líneas",
            "Un nivel de abstracción por función",
            "Evitar más de 3 parámetros",
        ],
        "example": """
**MAL:**
```python
def process_user(user):
    validate_user(user)
    save_to_database(user)
    send_welcome_email(user)
    log_action(user)
    update_stats(user)
```

**BIEN:**
```python
def process_user(user):
    if not validate_user(user):
        return False
    
    save_to_database(user)
    send_welcome_email(user)
    
def save_to_database(user):
    # Solo guardar
    pass
```""",
    },
    "comments": {
        "principle": "Comments Explain WHY, Not WHAT",
        "rules": [
            "Si el código necesita comentarios para explicar QUÉ hace, refactoriza",
            "Los comentarios deben explicar POR QUÉ, no qué",
            "Comments should express WHY, not WHAT",
            "Evitar comentarios redundantes",
        ],
        "example": """
**MAL:**
```python
# Increment counter by 1
counter += 1

# If user is active, send notification
if user.is_active:
    send_notification()
```

**BIEN:**
```python
# We increment to trigger the webhook
# because the user just completed onboarding
counter += 1
```""",
    },
    "formatting": {
        "principle": "Formatting Matters",
        "rules": [
            "Código vertical: Related code together",
            "Código horizontal: Consistent spacing",
            "Orden de declaración: Variables → Constructores → Métodos públicos → Métodos privados",
        ],
        "example": """
Blanco vertical para separación lógica.
Orden de lectura: arriba → abajo.
        """,
    },
    "error_handling": {
        "principle": "Error Handling",
        "rules": [
            "Usar excepciones en lugar de códigos de error",
            "No returnear null (o lanzar excepción)",
            "Mensajes de error informativos",
        ],
        "example": """
**MAL:**
```python
def get_user(id):
    user = db.query(id)
    if user is None:
        return None
    return user

result = get_user(123)
result.send_email()  # AttributeError!
```

**BIEN:**
```python
def get_user(id):
    user = db.query(id)
    if user is None:
        raise UserNotFoundError(f"User {id} not found")
    return user

try:
    user = get_user(123)
except UserNotFoundError:
    logger.error(f"User 123 not found")
```""",
    },
}

# ============================================
# CLEAN ARCHITECTURE
# ============================================

CLEAN_ARCHITECTURE = {
    "dependency_rule": {
        "principle": "Source code dependencies must point only inward, toward the higher-level policies.",
        "description": """
La regla de dependencia: El código depende hacia ADENTRO.
Los círculos más internos NO conocen los externos.

```    
┌─────────────────────────────────────────┐
│   Frameworks & Drivers (Outer Circle)   │
│   Web, DB, UI, External Services        │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│       Interface Adapters (Outer)        │
│   Controllers, Gateways, Presenters   │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│         Use Cases (Application)        │
│    Application-specific business rules  │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│           Entities (Inner)             │
│      Enterprise business rules          │
└─────────────────────────────────────────┘
```""",
    },
    "independence": {
        "description": "La arquitectura limpia hace el sistema independiente de:",
        "items": [
            "Frameworks (Django, React, Flask...)",
            "Bases de datos (MySQL, PostgreSQL, MongoDB...)",
            "Interfaces de usuario (Web, CLI, Mobile...)",
            "Agencias externas (APIs de terceros, cloud...)",
        ],
    },
    "benefits": [
        "El código de negocio no sabe nada del framework",
        "Puedes cambiar de base de datos sin tocar lógica de negocio",
        "Puedes cambiar la UI sin afectar las reglas de negocio",
        "Tests más fáciles (sin dependencias externas)",
        "Código más mantenible a largo plazo",
    ],
}

# ============================================
# CLEAN AGILE
# ============================================

CLEAN_AGILE = {
    "values": {
        "original_agile": [
            "Individuals and interactions over processes and tools",
            "Working software over comprehensive documentation",
            "Customer collaboration over contract negotiation",
            "Responding to change over following a plan",
        ],
        "clean_version": [
            "Customer satisfaction through early and continuous delivery",
            "Welcome changing requirements, even late in development",
            "Deliver working software frequently (1-4 weeks)",
            "Business and developers must work together daily",
            "Build projects around motivated individuals",
            "Face-to-face conversation is most efficient",
            "Working software is the primary measure of progress",
            "Sustainable pace indefinitely",
            "Continuous attention to technical excellence",
            "Simplicity (maximize work not done)",
            "Best architectures emerge from self-organizing teams",
            "Regular reflection and adjustment",
        ],
    },
    "practices": {
        "TDD": {
            "description": "Test-Driven Development: Red-Green-Refactor",
            "steps": [
                "1. RED: Escribe un test que falla",
                "2. GREEN: Escribe el mínimo código para pasar el test",
                "3. REFACTOR: Mejora el código manteniendo los tests pasando",
            ],
        },
        "CI": {
            "description": "Continuous Integration",
            "rules": [
                "Integrar código diariamente",
                "Cada integración pasa todos los tests",
                "Broken build = máxima prioridad",
            ],
        },
        "pair_programming": {
            "description": "Driver + Navigator",
            "benefits": ["Mayor calidad de código", "Sharing de conocimiento", "Revisión continua"],
        },
    },
}

# ============================================
# THE BOY SCOUT RULE
# ============================================

BOY_SCOUT_RULE = {
    "quote": "Always leave the code better than you found it.",
    "description": """
El código se deteriora con el tiempo.
Cada vez que toques un archivo, déjalo MEJOR de lo que estaba.

pequeñas mejoras acumuladas = código mantenible
    """,
    "examples": [
        "Rename variables confusos",
        "Extraer funciones largas",
        "Añadir tipos (Type Hints)",
        "Reducir duplicación",
        "Mejorar nombres",
    ],
}

# ============================================
# GOLDEN RULES DE UNCLE BOB
# ============================================

GOLDEN_RULES = [
    "The only way to go fast, is to go well.",
    "Functions should do one thing. They should do it well. They should do it only.",
    "Coding is not about what you can make machines do. It's about what you can make yourself do in a reasonable amount of time.",
    "The ratio of time spent reading vs. writing is well over 10 to 1.",
    "Architecture represents the significant design decisions, where significant means hard to change.",
    "Professionalism is about putting responsibility for our own work.",
    "Quality is not an afterthought. It must be built in from the start.",
]

# ============================================
# EJEMPLOS POR LENGUAJE
# ============================================

CODE_EXAMPLES = {
    "python": {
        "dependency_injection": """
from abc import ABC, abstractmethod
from typing import Protocol

class Storage(Protocol):
    def save(self, data: dict): ...

class DatabaseStorage:
    def save(self, data: dict):
        # Implementación real
        pass

class FileStorage:
    def save(self, data: dict):
        # Implementación archivo
        pass

class UserService:
    def __init__(self, storage: Storage):  # Dependency Injection
        self.storage = storage
    
    def create_user(self, user_data):
        self.storage.save(user_data)
"""
    },
    "typescript": {
        "dependency_inversion": """
// Protocol/Interface
interface Logger {
    log(message: string): void;
}

// Implementations
class ConsoleLogger implements Logger {
    log(message: string): void {
        console.log(message);
    }
}

class FileLogger implements Logger {
    log(message: string): void {
        // Write to file
    }
}

// High-level module depends on abstraction
class UserService {
    constructor(private logger: Logger) {}
    
    createUser(user: User): void {
        this.logger.log('Creating user');
    }
}
"""
    },
    "java": {
        "clean_architecture": """
// Entity (Inner Circle)
public class User {
    private String id;
    private String name;
    // Getters, setters, business logic
}

// Use Case (Application)
public interface CreateUserUseCase {
    User execute(String name, String email);
}

// Interface Adapter (Outer)
@Service
public class CreateUserService implements CreateUserUseCase {
    private UserRepository userRepository;
    
    public User execute(String name, String email) {
        // Business logic
        // Use repository abstraction, not concrete DB
        return userRepository.save(new User(name, email));
    }
}

// Dependency Injection
@Configuration
public class AppConfig {
    @Bean
    public UserService createUserService() {
        return new UserService(userRepository());
    }
}
"""
    },
}

# ============================================
# FUNCIONES
# ============================================


async def get_clean_arch_info(
    principle: str = "solid", language: str = "general", format: str = "explanation"
) -> str:
    """Obtiene información de Clean Architecture."""

    principle_lower = principle.lower()

    # SOLID
    if principle_lower == "solid":
        return format_solid(principle_lower, format)

    # Dependency Rule
    elif principle_lower in ["dependency_rule", "dependency"]:
        return format_dependency_rule(format)

    # Clean Code
    elif principle_lower in ["clean_code", "cleancode"]:
        return format_clean_code(principle_lower, format)

    # Clean Architecture
    elif principle_lower in ["clean_architecture", "cleanarchitecture"]:
        return format_clean_arch(format)

    # Clean Agile
    elif principle_lower in ["clean_agile", "cleanagile"]:
        return format_clean_agile(format)

    # Boy Scout Rule
    elif principle_lower in ["boy_scout_rule", "boyscout"]:
        return format_boy_scout(format)

    return f"""❌ Principio '{principle}' no encontrado.

**Principios disponibles:**
- solid: Single Responsibility, OCP, LSP, ISP, DIP
- dependency_rule: Clean Architecture Dependency Rule
- clean_code: Clean Code principles
- clean_architecture: Clean Architecture
- clean_agile: Clean Agile methodology
- boy_scout_rule: Always leave the code better"""


def format_solid(principle: str, format: str) -> str:
    """Formatea información de SOLID."""

    # Si es "solid" general, mostrar todos
    if format == "explanation":
        lines = ["# Principios SOLID", ""]

        for key, p in SOLID_PRINCIPLES.items():
            lines.append(f"## {key}: {p['name']}")
            lines.append(f"**{p['principle']}**")
            lines.append("")
            lines.append(p["description"])
            lines.append("")
            lines.append("**Beneficios:**")
            for b in p["benefits"]:
                lines.append(f"- {b}")
            lines.append("")

        return "\n".join(lines)

    # Si es un principio específico
    if principle in SOLID_PRINCIPLES:
        p = SOLID_PRINCIPLES[principle]
        return f"""## {principle}: {p["name"]}

**{p["principle"]}**

{p["description"]}

### Ejemplo
```
{p["example"]}
```

**Beneficios:**
{chr(10).join(f"- {b}" for b in p["benefits"])}"""

    return "Principio SOLID no encontrado"


def format_dependency_rule(format: str) -> str:
    """Formatea la Dependency Rule."""

    if format == "explanation":
        return """## Dependency Rule

**Source code dependencies must point only inward, toward the higher-level policies.**

```    
┌─────────────────────────────────────────┐
│   Frameworks & Drivers (Outer Circle)   │
│   Web, DB, UI, External Services        │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│       Interface Adapters (Outer)        │
│   Controllers, Gateways, Presenters   │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│         Use Cases (Application)        │
│    Application-specific business rules  │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│           Entities (Inner)             │
│      Enterprise business rules          │
└─────────────────────────────────────────┘
```

**Independencia de:**
- Frameworks
- Bases de datos
- Interfaces de usuario
- Agencias externas
"""

    return CLEAN_ARCHITECTURE["dependency_rule"]["principle"]


def format_clean_code(principle: str, format: str) -> str:
    """Formatea Clean Code."""

    if format == "explanation":
        lines = ["# Clean Code Principles", ""]

        for key, p in CLEAN_CODE_PRINCIPLES.items():
            lines.append(f"## {p['principle']}")
            lines.append("")
            for rule in p["rules"]:
                lines.append(f"- {rule}")
            lines.append("")

        return "\n".join(lines)

    return "Principio no encontrado"


def format_clean_arch(format: str) -> str:
    """Formatea Clean Architecture."""

    return f"""## Clean Architecture

**{CLEAN_ARCHITECTURE["dependency_rule"]["principle"]}**

### Beneficios:
{chr(10).join(f"- {b}" for b in CLEAN_ARCHITECTURE["benefits"])}

### Independencia de:
{chr(10).join(f"- {i}" for i in CLEAN_ARCHITECTURE["independence"]["items"])}
"""


def format_clean_agile(format: str) -> str:
    """Formatea Clean Agile."""

    lines = ["# Clean Agile", ""]

    lines.append("## Valores Originales Agile:")
    for v in CLEAN_AGILE["values"]["original_agile"]:
        lines.append(f"- {v}")

    lines.append("")
    lines.append("## Clean Version:")
    for v in CLEAN_AGILE["values"]["clean_version"]:
        lines.append(f"- {v}")

    lines.append("")
    lines.append("## Prácticas:")
    for key, p in CLEAN_AGILE["practices"].items():
        lines.append(f"### {key}: {p['description']}")
        for step in p["steps"]:
            lines.append(f"- {step}")
        lines.append("")

    return "\n".join(lines)


def format_boy_scout(format: str) -> str:
    """Formatea el Boy Scout Rule."""

    return f"""## Boy Scout Rule

**"{BOY_SCOUT_RULE["quote"]}"**

{BOY_SCOUT_RULE["description"]}

### Ejemplos de mejora:
{chr(10).join(f"- {e}" for e in BOY_SCOUT_RULE["examples"])}

**Golden Rules:**
{chr(10).join(f"- {r}" for r in GOLDEN_RULES[:3])}"""
