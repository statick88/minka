"""
Minka Quotes - Citas Estilo Kevin Mitnick

Colección de citas memorables para inspirar curiosity y hacking mindset.
"""

import random
from typing import Dict, List

# ============================================
# CITAS DE KEVIN MITNICK
# ============================================

MITNICK_QUOTES = {
    "curiosity": [
        "La curiosidad es lo que me inició en esto. Sigue siendo mi motor principal.",
        "Los mejores hacks no requieren código. Requieren imaginación.",
        "¿Cómo funciona esto realmente? Esa pregunta me llevó a descubrir sistemas enteros.",
        "La curiosidad es mi superpower. La seguridad es mi pasión.",
        "Todo empieza con una pregunta. ¿Qué pasa si...?",
    ],
    "perspective": [
        "Para protegerte, necesitas pensar como quien te ataca.",
        "La seguridad no es un producto. Es un proceso.",
        "Cada vulnerabilidad tiene una historia. Cada exploit, un protagonista.",
        "No se trata de si te van a atacar. Es cuándo.",
        "El atacante solo necesita tener razón una vez. El defensor debe estar correcto siempre.",
    ],
    "social_engineering": [
        "El eslabón más débil de la cadena de seguridad es el humano.",
        "Con las palabras correctas, puedes lograr cualquier cosa.",
        "La ingeniería social usa influencia y persuasión para engañar.",
        "No necesitas ser un genio técnico. Solo necesitas entender cómo piensan las personas.",
        "El teléfono es el arma más peligrosa que existe.",
    ],
    "education": [
        "Enseño lo que aprendí... para que otros no tengan que aprenderlo de la manera difícil.",
        "La mejor defensa es entender completamente cómo funciona el ataque.",
        "No se trata de causar daño. Se trata de proteger.",
        "Mi objetivo ahora es enseñar. Que los sistemas sean más seguros.",
    ],
    "hacking": [
        "Los hackers no rompen sistemas. Los convencemos de mostrarnos sus secretos.",
        "El verdadero hacking es sobre entender, no destruir.",
        "Cada sistema tiene una puerta. Solo hay que encontrar la llave.",
        "La belleza de un hack está en su simplicidad.",
    ],
}

# ============================================
# CITAS DE ROBERT C. MARTIN (UNCLE BOB)
# ============================================

UNCLE_BOB_QUOTES = {
    "clean_code": [
        "The only way to go fast, is to go well.",
        "Functions should do one thing. They should do it well. They should do it only.",
        "Coding is not about what you can make machines do. It's about what you can make yourself do.",
        "The ratio of time spent reading vs. writing is well over 10 to 1.",
        "Comments should explain WHY, not WHAT.",
    ],
    "architecture": [
        "Architecture represents the significant design decisions, where significant means hard to change.",
        "Source code dependencies must point only inward, toward the higher-level policies.",
        "Good architecture makes the system easy to understand, easy to develop, easy to maintain.",
        "The goal of software architecture is to minimize the human resources required to build and maintain the system.",
    ],
    "professionalism": [
        "Professionalism is about taking responsibility for your own work.",
        "We must be honest about our capabilities and limitations.",
        "Quality is not an afterthought. It must be built in from the start.",
        "Always leave the code better than you found it. (Boy Scout Rule)",
    ],
    "agile": [
        "Clean Agile is about the original values and principles of Agile.",
        "Individuals and interactions over processes and tools.",
        "Working software over comprehensive documentation.",
        "Customer collaboration over contract negotiation.",
    ],
}

# ============================================
# CITAS DE HACKERS FAMOSOS
# ============================================

HACKER_QUOTES = {
    "grace_hopper": ["El humano más difícil de enseñar es aquel que ya sabe hacerlo."],
    "alan_turing": [
        "A veces son las personas que nadie imagina nada las que hacen las cosas que nadie puede imaginar."
    ],
    "rich_stallman": ["El software libre es un tema de libertad, no de precio."],
    "grace_murray_hopper": ["Es más fácil pedir perdón que pedir permiso."],
    "edsger_dijkstra": [
        "La simplicidad es un prerrequisito para la confiabilidad.",
        "Si la depuración es el proceso de eliminar bugs, entonces la programación debe ser el proceso de ponerlos.",
    ],
}

# ============================================
# CITAS DE CIBERSEGURIDAD
# ============================================

SECURITY_QUOTES = [
    "La seguridad es un proceso, no un producto.",
    "No existe seguridad perfecta. Solo diferentes niveles de riesgo.",
    "Si algo puede salir mal, saldrá mal. (Ley de Murphy)",
    "Defensa en profundidad. Múltiples capas de seguridad.",
    "Assume breach. Asume que ya están dentro.",
    "Elige la seguridad por diseño, no como afterthought.",
    "Primero, no causar daño. (Principio Hipocrático)",
    "La confianza es un riesgo. La verificación es una mitigación.",
]

# ============================================
# CITAS DE EDUCADORES TECH (Rockstars)
# ============================================

EDUCATOR_QUOTES = {
    "midudev_style": [
        "Vamos a verlo en código. La teoría está bien, pero la práctica...",
        "No te preocupes si no lo entiendes ahora. Vamos paso a paso.",
        "Esto es lo que hace que la programación sea tan fascinante.",
    ],
    "mouredev_style": [
        "Y esto es lo que importa en producción.",
        "En el mundo real, esto es lo que cuenta.",
        "Hazlo funcionar. Luego, hazlo bien.",
    ],
    "s4vitar_style": [
        "La vulnerabilidad está ahí. Solo hay que saber dónde mirar.",
        "El análisis técnico profundo es lo que separa a los buenos de los excelentes.",
        "Entender el 'cómo' es más importante que el 'qué'.",
    ],
    "gentleman_style": [
        "El testing no es opcional. Es parte del código.",
        "Código limpio, código mantenible, código que dura.",
        "La calidad no es negociable.",
    ],
}

# ============================================
# CATEGORÍAS PARA BÚSQUEDA
# ============================================

CATEGORIES = {
    "curiosity": MITNICK_QUOTES["curiosity"],
    "perspective": MITNICK_QUOTES["perspective"],
    "social_engineering": MITNICK_QUOTES["social_engineering"],
    "education": MITNICK_QUOTES["education"],
    "hacking": MITNICK_QUOTES["hacking"],
    "clean_code": UNCLE_BOB_QUOTES["clean_code"],
    "architecture": UNCLE_BOB_QUOTES["architecture"],
    "professionalism": UNCLE_BOB_QUOTES["professionalism"],
    "agile": UNCLE_BOB_QUOTES["agile"],
    "security": SECURITY_QUOTES,
    "midudev": EDUCATOR_QUOTES["midudev_style"],
    "mouredev": EDUCATOR_QUOTES["mouredev_style"],
    "s4vitar": EDUCATOR_QUOTES["s4vitar_style"],
    "gentleman": EDUCATOR_QUOTES["gentleman_style"],
}

# ============================================
# FUNCIÓN PRINCIPAL
# ============================================


async def get_quote(category: str = "curiosity", tone: str = "inspirational") -> str:
    """Obtiene una cita aleatoria según la categoría."""

    # Normalizar categoría
    category_lower = category.lower()

    # Buscar categoría
    if category_lower in CATEGORIES:
        quotes = CATEGORIES[category_lower]
    elif category_lower in ["mitnick", "kevin"]:
        all_mitnick = (
            MITNICK_QUOTES["curiosity"]
            + MITNICK_QUOTES["perspective"]
            + MITNICK_QUOTES["social_engineering"]
            + MITNICK_QUOTES["education"]
            + MITNICK_QUOTES["hacking"]
        )
        quotes = all_mitnick
    elif category_lower in ["uncle_bob", "robert_martin", "clean"]:
        all_uncle_bob = (
            UNCLE_BOB_QUOTES["clean_code"]
            + UNCLE_BOB_QUOTES["architecture"]
            + UNCLE_BOB_QUOTES["professionalism"]
        )
        quotes = all_uncle_bob
    else:
        # Categoría no encontrada, devolver cita aleatoria
        all_quotes = MITNICK_QUOTES["curiosity"] + UNCLE_BOB_QUOTES["clean_code"] + SECURITY_QUOTES
        quotes = all_quotes

    # Seleccionar cita
    quote = random.choice(quotes)

    # Determinar autor
    if category_lower in [
        "curiosity",
        "perspective",
        "social_engineering",
        "education",
        "hacking",
        "mitnick",
        "kevin",
    ]:
        author = "— Kevin Mitnick"
    elif category_lower in [
        "clean_code",
        "architecture",
        "professionalism",
        "agile",
        "uncle_bob",
        "robert_martin",
        "clean",
    ]:
        author = "— Robert C. Martin (Uncle Bob)"
    elif category_lower in ["security"]:
        author = "— ciberseguridad"
    else:
        author = ""

    # Formatear según tono
    if tone == "inspirational":
        return f"💡 *{quote}*\n\n{author}"
    elif tone == "humorous":
        return f"😄 {quote}\n\n{author}"
    else:  # technical
        return f"```\n{quote}\n```\n\n{author}"


async def get_random_quote() -> str:
    """Obtiene una cita aleatoria."""
    all_quotes = MITNICK_QUOTES["curiosity"] + UNCLE_BOB_QUOTES["clean_code"] + SECURITY_QUOTES
    quote = random.choice(all_quotes)
    author = random.choice(["— Kevin Mitnick", "— Robert C. Martin", "— Anónimo"])
    return f"💡 *{quote}*\n\n{author}"
