"""
Minka Experts Database - Researchers and Institutions

Biblioteca de investigadores y expertos en ciberseguridad e IA.
"""

# ============================================
# NIVEL 1: TINNING AWARD WINNERS
# ============================================

RESEARCHERS = {
    # Turing Award Winners
    "geoffrey_hinton": {
        "name": "Geoffrey Hinton",
        "titles": ["Turing Award Winner", "Godfather of Deep Learning"],
        "affiliations": ["University of Toronto", "Google DeepMind"],
        "expertise": ["Deep Learning", "Neural Networks", "Backpropagation"],
        "key_contributions": [
            "Backpropagation algorithm",
            "Capsule Networks",
            "Deep Learning revolution",
        ],
        "papers": ["Learning Representations by Back-propagating Errors (1986)"],
        "citation": "Hinton, G. E., et al. (1986). Learning Representations by Back-propagating Errors. Nature.",
    },
    "yoshua_bengio": {
        "name": "Yoshua Bengio",
        "titles": ["Turing Award Winner", "AI Safety Pioneer"],
        "affiliations": ["Université de Montréal", "MILA", "Google"],
        "expertise": ["Deep Learning", "AI Safety", "Attention Mechanisms"],
        "key_contributions": [
            "GANs (with Ian Goodfellow)",
            "Neural Machine Translation",
            "AI Safety research",
        ],
        "papers": [
            "Learning Deep Architectures for AI (2009)",
            "Neural Probabilistic Language Models",
        ],
        "citation": "Bengio, Y. (2009). Learning Deep Architectures for AI. Foundations and Trends in ML.",
    },
    "ian_goodfellow": {
        "name": "Ian Goodfellow",
        "titles": ["GAN Creator", "Apple Research"],
        "affiliations": ["Apple", "Google Brain", "Stanford"],
        "expertise": ["Generative AI", "Adversarial Machine Learning", "Deep Learning"],
        "key_contributions": ["Generative Adversarial Networks (GANs)", "Deep Learning textbook"],
        "papers": [
            "Explaining and Harnessing Adversarial Examples (2014)",
            "Generative Adversarial Networks (2014)",
        ],
        "citation": "Goodfellow, I., et al. (2014). Explaining and Harnessing Adversarial Examples. arXiv.",
    },
    # ============================================
    # NIVEL 2: LEADING SECURITY RESEARCHERS
    # ============================================
    "dawn_song": {
        "name": "Dawn Song",
        "titles": ["Professor UC Berkeley", "MacArthur Fellow", "AI2050 Senior Fellow"],
        "affiliations": ["UC Berkeley", "Oasis Labs", "Berkeley RDI"],
        "expertise": ["AI Security", "Blockchain", "Secure Machine Learning", "Smart Contracts"],
        "key_contributions": [
            "Oyente (smart contracts security)",
            "DataSentinel: Prompt Injection Detection (IEEE S&P 2025)",
            "Agentic AI MOOC (32K+ enrolled)",
        ],
        "awards": ["Distinguished Paper Award IEEE S&P 2025"],
        "papers": ["DataSentinel: A Game-Theoretic Detection of Prompt Injection Attacks (2025)"],
        "citation": "Song, D., et al. (2025). DataSentinel: Prompt Injection Detection. IEEE S&P.",
    },
    "nicholas_carlini": {
        "name": "Nicholas Carlini",
        "titles": ["Research Scientist Anthropic", "60K+ citations", "Best Paper Awards"],
        "affiliations": ["Anthropic", "Google Brain", "DeepMind", "UC Berkeley"],
        "expertise": [
            "Adversarial Machine Learning",
            "Security",
            "Neural Networks",
            "LLM Security",
        ],
        "key_contributions": [
            "Carlini-Wagner attacks (C&W)",
            "Best paper awards: IEEE S&P, USENIX Security (2x), ICML (3x)",
        ],
        "papers": [
            "Adversarial Examples Are Not Easily Detected (2017)",
            "On Evaluating Adversarial Robustness (2019)",
            "Comprehensive Assessment of ML Security (2024)",
        ],
        "citation": "Carlini, N., & Wagner, D. (2017). Adversarial Examples Are Not Easily Detected. ACM AISec.",
    },
    "alina_oprea": {
        "name": "Alina Oprea",
        "titles": [
            "Professor Northeastern",
            "Google Security Award 2019",
            "CyLab Distinguished Alumni 2024",
        ],
        "affiliations": ["Northeastern University", "RSA Laboratories", "NIST"],
        "expertise": ["Cloud Security", "Machine Learning Security", "Adversarial ML"],
        "key_contributions": [
            "Google Security Award 2019",
            "NIST AI 100-2e2025 co-author",
            "Cloud security metrics",
        ],
        "papers": ["Adversarial ML Taxonomy (NIST 2025)", "Cloud Security Research"],
        "citation": "Oprea, A., & Vassilev, A. (2025). Adversarial ML Taxonomy. NIST AI 100-2e2025.",
    },
    "ben_zhao": {
        "name": "Ben Zhao",
        "titles": ["TIME100 AI 2024", "Professor UChicago"],
        "affiliations": ["University of Chicago", "SAND Lab"],
        "expertise": ["Adversarial ML", "AI Defense", "Security", "Privacy"],
        "key_contributions": [
            "Glaze: Protecting Artists from Style Theft",
            "Nightshade: Poisoning attacks on generative AI",
            "TIME100 AI (2024)",
        ],
        "papers": [
            "Glaze: Protecting Artists from Style Theft (USENIX 2024)",
            "Nightshade Attacks (2024)",
        ],
        "citation": "Zhao, B., et al. (2024). Glaze: Protecting Artists from Style Theft. USENIX Security.",
    },
    "heather_zheng": {
        "name": "Heather Zheng",
        "titles": ["Professor UChicago", "SAND Lab Co-director"],
        "affiliations": ["University of Chicago", "SAND Lab"],
        "expertise": ["Adversarial ML", "Security", "Privacy"],
        "key_contributions": ["Glaze", "Nightshade", "AI security research"],
        "papers": ["Glaze: Protecting Artists (USENIX 2024)"],
        "citation": "Zheng, H., et al. (2024). Glaze: Protecting Artists from Style Theft. USENIX Security.",
    },
    "bruce_schneier": {
        "name": "Bruce Schneier",
        "titles": ["Security Expert", "Author 12+ books", "Fellow Harvard Kennedy School"],
        "affiliations": ["Independent", "Harvard Kennedy School", "IBM Security"],
        "expertise": ["Cryptography", "Security", "Privacy", "Policy"],
        "key_contributions": [
            "Blowfish cipher",
            "Twofish cipher",
            "Schneier's Laws",
            "12+ security books",
        ],
        "books": [
            "Applied Cryptography (1993)",
            "Secrets and Lies (2000)",
            "Schneier on Security (2008)",
            "Data and Goliath (2015)",
        ],
        "citation": "Schneier, B. (2015). Data and Goliath. W.W. Norton.",
    },
    "apostol_vassilev": {
        "name": "Apostol Vassilev",
        "titles": ["NIST", "AML Taxonomy Lead"],
        "affiliations": ["National Institute of Standards and Technology (NIST)"],
        "expertise": ["Adversarial Machine Learning", "AI Security Standards", "Security Taxonomy"],
        "key_contributions": [
            "NIST AI 100-2e2025: Adversarial ML Taxonomy",
            "AI security standards development",
        ],
        "papers": ["Adversarial Machine Learning: A Taxonomy and Terminology (NIST 2025)"],
        "citation": "Vassilev, A., et al. (2025). Adversarial ML: A Taxonomy. NIST AI 100-2e2025.",
    },
    # ============================================
    # NIVEL 3: RISING STARS & PRACTITIONERS
    # ============================================
    "li_li": {
        "name": "Li Li",
        "titles": ["Researcher"],
        "affiliations": ["Researcher"],
        "expertise": ["Adversarial Examples", "Cybersecurity"],
        "key_contributions": [
            "Comprehensive Survey on Adversarial Examples in Cybersecurity (2024)"
        ],
        "papers": ["Comprehensive Survey on Adversarial Examples in Cybersecurity (arXiv 2024)"],
        "citation": "Li, L. (2024). Comprehensive Survey on Adversarial Examples in Cybersecurity. arXiv.",
    },
    "phil_roth": {
        "name": "Phil Roth",
        "titles": ["CrowdStrike Researcher"],
        "affiliations": ["CrowdStrike"],
        "expertise": ["Malware Detection", "Machine Learning", "EMBER Benchmark"],
        "key_contributions": ["EMBER Benchmark development", "EMBER2024"],
        "papers": [
            "EMBER2024: A Benchmark Dataset for Holistic Evaluation of Malware Classifiers (2025)"
        ],
        "citation": "Roth, P., et al. (2025). EMBER2024: Malware Benchmark. arXiv.",
    },
    "hyrum_anderson": {
        "name": "Hyrum Anderson",
        "titles": ["CrowdStrike", "NIST Co-author"],
        "affiliations": ["CrowdStrike", "NIST"],
        "expertise": ["Machine Learning Security", "Malware Detection", "EMBER"],
        "key_contributions": ["EMBER benchmark", "NIST AI 100-2e2025 co-author"],
        "papers": ["EMBER Benchmark papers", "NIST AML Taxonomy"],
        "citation": "Anderson, H., et al. (2025). EMBER2024: Malware Benchmark. arXiv.",
    },
    "edward_raff": {
        "name": "Edward Raff",
        "titles": ["Chief Scientist", "EMBER Author"],
        "affiliations": ["CrowdStrike", "Booz Allen Hamilton"],
        "expertise": ["Machine Learning", "Malware Detection", "Cybersecurity"],
        "key_contributions": ["EMBER benchmark", "ML for malware detection"],
        "papers": ["EMBER: A Benchmark Dataset for Malware Detection (2019)", "EMBER2024"],
        "citation": "Raff, E., et al. (2019). EMBER: A Benchmark Dataset for Malware Detection. arXiv.",
    },
    "scott_freitas": {
        "name": "Scott Freitas",
        "titles": ["Researcher"],
        "affiliations": ["Researcher"],
        "expertise": ["SOC Automation", "AI for Security"],
        "key_contributions": ["AI-Driven Guided Response for SOCs (2024)"],
        "papers": ["AI-Driven Guided Response for Security Operation Centers (arXiv 2024)"],
        "citation": "Freitas, S., et al. (2024). AI-Driven Guided Response for SOCs. arXiv.",
    },
    "ambrish_rawat": {
        "name": "Ambrish Rawat",
        "titles": ["Red Team Researcher"],
        "affiliations": ["Microsoft"],
        "expertise": ["GenAI Red Teaming", "LLM Security"],
        "key_contributions": ["Attack Atlas: Red Teaming GenAI (2024)"],
        "papers": ["Attack Atlas: A Practitioner Perspective on Red Teaming GenAI (arXiv 2024)"],
        "citation": "Rawat, A., et al. (2024). Attack Atlas: Red Teaming GenAI. arXiv.",
    },
    "katherine_huang": {
        "name": "Katherine Huang",
        "titles": ["NVIDIA Developer"],
        "affiliations": ["NVIDIA"],
        "expertise": ["SOC Automation", "Morpheus Framework", "LLMs for Security"],
        "key_contributions": ["NVIDIA Morpheus documentation", "AI for SOC blog posts"],
        "papers": ["Augmenting SOCs with NVIDIA Morpheus (NVIDIA Blog 2024)"],
        "citation": "Huang, K., & Nandakumar, D. (2024). Augmenting SOCs with NVIDIA Morpheus. NVIDIA Blog.",
    },
}

# ============================================
# INSTITUCIONES
# ============================================

INSTITUTIONS = {
    "nist": {
        "name": "NIST",
        "full_name": "National Institute of Standards and Technology",
        "focus": "Standards & AI Security",
        "key_publications": [
            "AI 100-2e2025: Adversarial ML Taxonomy",
            "Cybersecurity Framework",
            "SP 800-53 Security Controls",
        ],
        "url": "https://www.nist.gov/",
        "citation": "NIST. (2025). AI 100-2e2025: Adversarial Machine Learning Taxonomy.",
    },
    "mit_csail": {
        "name": "MIT CSAIL",
        "full_name": "MIT Computer Science and Artificial Intelligence Laboratory",
        "focus": "AI & Security Research",
        "key_people": ["Tim Berners-Lee", "Shafi Goldwasser", "Ronald Rivest"],
        "research_areas": ["Cryptography", "AI", "Security", "Systems"],
        "url": "https://www.csail.mit.edu/",
    },
    "cmu_cylab": {
        "name": "CMU CyLab",
        "full_name": "Carnegie Mellon University CyLab",
        "focus": "Security & Privacy Research",
        "key_people": ["Vyas Sekar", "Nicolas Brunhart-Luppero"],
        "research_areas": ["Network Security", "Privacy", "Cryptography", "Forensics"],
        "url": "https://www.cylab.cmu.edu/",
    },
    "ucb_rdi": {
        "name": "UC Berkeley RDI",
        "full_name": "UC Berkeley Center on Responsible Decentralized Intelligence",
        "focus": "Responsible AI & Decentralized Systems",
        "key_people": ["Dawn Song"],
        "research_areas": ["AI Safety", "Blockchain", "Secure ML"],
        "url": "https://rdi.berkeley.edu/",
    },
    "uchicago_sand": {
        "name": "UChicago SAND Lab",
        "full_name": "University of Chicago SAND Lab",
        "focus": "Adversarial ML & AI Defense",
        "key_people": ["Ben Zhao", "Heather Zheng"],
        "research_areas": ["Adversarial ML", "AI Security", "Privacy"],
        "url": "https://sandlab.cs.uchicago.edu/",
    },
    "anthropic": {
        "name": "Anthropic",
        "focus": "AI Safety & Constitutional AI",
        "key_people": ["Dario Amodei", "Nicholas Carlini"],
        "research_areas": ["LLM Safety", "Constitutional AI", "AI Alignment"],
        "url": "https://www.anthropic.com/",
    },
    "google_deepmind": {
        "name": "Google DeepMind",
        "focus": "AI Research & Security Applications",
        "key_people": ["Ian Goodfellow", "Demis Hassabis"],
        "research_areas": ["Deep Learning", "AI Safety", "ML Security"],
        "url": "https://deepmind.google/",
    },
    "crowdstrike": {
        "name": "CrowdStrike",
        "focus": "Endpoint Security & ML for Malware Detection",
        "key_people": ["Phil Roth", "Hyrum Anderson", "Edward Raff"],
        "research_areas": ["Malware Detection", "Threat Intelligence", "EMBER Benchmark"],
        "url": "https://www.crowdstrike.com/",
    },
    "microsoft_security": {
        "name": "Microsoft Security",
        "focus": "Enterprise Security & AI for SOC",
        "key_products": ["Microsoft Copilot for Security", "Azure Sentinel"],
        "research_areas": ["SOC Automation", "Threat Intelligence", "AI Security"],
        "url": "https://www.microsoft.com/security",
    },
    "nvidia_morpheus": {
        "name": "NVIDIA Morpheus",
        "focus": "AI-powered Security Pipeline",
        "research_areas": ["Real-time Security", "LLM for Security", "Digital Fingerprinting"],
        "url": "https://developer.nvidia.com/morpheus",
    },
}

# ============================================
# FUNCIONES DE BÚSQUEDA
# ============================================


async def search_experts(query: str, format: str = "brief") -> str:
    """Busca investigadores e instituciones."""
    results = []
    query_lower = query.lower()

    # Buscar en investigadores
    for key, researcher in RESEARCHERS.items():
        # Por nombre
        if query_lower in researcher["name"].lower():
            results.append(format_researcher(researcher, format))
            continue

        # Por expertise
        for exp in researcher.get("expertise", []):
            if query_lower in exp.lower():
                results.append(format_researcher(researcher, format))
                break
        else:
            # Por affiliation
            for aff in researcher.get("affiliations", []):
                if query_lower in aff.lower():
                    results.append(format_researcher(researcher, format))
                    break

    # Buscar en instituciones
    for key, inst in INSTITUTIONS.items():
        if query_lower in inst["name"].lower() or query_lower in inst.get("focus", "").lower():
            results.append(format_institution(inst, format))

    if not results:
        return f"❌ No se encontraron expertos para '{query}'. Prueba con: Carlini, Song, Oprea, NIST, CMU, CrowdStrike."

    return "\n\n".join(results)


def format_researcher(researcher: dict, format: str) -> str:
    """Formatea un investigador según el formato solicitado."""
    if format == "brief":
        return f"""**👤 {researcher["name"]}**
{" | ".join(researcher.get("titles", [])[:2])}
📍 {", ".join(researcher.get("affiliations", [])[:2])}
🏷️ {", ".join(researcher.get("expertise", [])[:3])}"""

    elif format == "citation":
        return f"""**{researcher["name"]}**

{researcher.get("citation", "No citation available")}

🔗 Papers: {", ".join(researcher.get("papers", [])[:2])}"""

    else:  # detailed
        return f"""**👤 {researcher["name"]}**
{" | ".join(researcher.get("titles", []))}

📍 **Affiliations:**
{chr(10).join(f"  • {a}" for a in researcher.get("affiliations", []))}

🏷️ **Expertise:**
{chr(10).join(f"  • {e}" for e in researcher.get("expertise", []))}

🔑 **Key Contributions:**
{chr(10).join(f"  • {c}" for c in researcher.get("key_contributions", [])[:3])}

📚 **Papers:**
{chr(10).join(f"  • {p}" for p in researcher.get("papers", [])[:2])}

📖 **Citation:**
{researcher.get("citation", "N/A")}"""


def format_institution(inst: dict, format: str) -> str:
    """Formatea una institución según el formato solicitado."""
    if format == "brief":
        return f"""**🏛️ {inst["name"]}**
{inst.get("focus", "N/A")}
🔗 {inst.get("url", "N/A")}"""

    else:
        return f"""**🏛️ {inst["name"]}**
**Full Name:** {inst.get("full_name", inst["name"])}
**Focus:** {inst.get("focus", "N/A")}
**Key People:** {", ".join(inst.get("key_people", [])[:3]) if inst.get("key_people") else "N/A"}
**Research Areas:** {", ".join(inst.get("research_areas", [])[:3])}
🔗 {inst.get("url", "N/A")}"""


async def get_citation(researcher_name: str) -> str:
    """Obtiene formato de cita IEEE para un investigador."""
    query_lower = researcher_name.lower()

    for key, researcher in RESEARCHERS.items():
        if query_lower in researcher["name"].lower():
            return f"""**Citación IEEE para {researcher["name"]}**

```
{researcher.get("citation", "No citation available")}
```
"""

    return f"Cita no encontrada para '{researcher_name}'. Prueba con: Nicholas Carlini, Dawn Song, Alina Oprea."
