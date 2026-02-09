"""
Minka AI Security Tools - IA Applied to Cybersecurity

Recursos de IA para ciberseguridad:
- Malware Detection con ML
- SOC Automation
- Offensive AI / AI Red Teaming
- AI Defense
"""

# ============================================
# MALWARE DETECTION CON ML
# ============================================

MALWARE_DETECTION = {
    "ember": {
        "name": "EMBER (Extensible Malware Benchmark)",
        "description": "Benchmark para evaluación de clasificadores de malware",
        "version": "EMBER 2024",
        "researchers": ["Hyrum Anderson", "Phil Roth", "Edward Raff"],
        "organization": "CrowdStrike",
        "link": "https://github.com/elastic/ember",
        "metrics": ["AUC-ROC", "AP", "TPR@FPR"],
        "paper": "EMBER2024: A Benchmark Dataset for Holistic Evaluation",
    },
    "techniques": {
        "static_analysis": {
            "description": "Análisis de características sin ejecutar",
            "features": ["PE headers", "byte N-grams", "strings", "imports"],
            "models": ["Random Forest", "XGBoost", "LightGBM"],
        },
        "dynamic_analysis": {
            "description": "Análisis durante ejecución",
            "features": ["API calls", "network traffic", "file operations"],
            "models": ["LSTM", "GRU", "Transformer"],
        },
        "hybrid": {
            "description": "Combinación de static + dynamic",
            "features": ["multimodal", "temporal patterns"],
            "models": ["Ensemble", "Graph Neural Networks"],
        },
    },
}

# ============================================
# SOC AUTOMATION
# ============================================

SOC_AI_TOOLS = {
    "microsoft_copilot_security": {
        "name": "Microsoft Copilot for Security",
        "description": "AI assistant para SOC con GenAI",
        "impact": "30.13% reducción en MTTR (mean time to resolution)",
        "paper": "AI-Driven Guided Response for Security Operation Centers (2024)",
        "authors": ["Scott Freitas", "Jovan Kalajdjieski", "Amir Gharib", "Robert McCann"],
        "link": "https://www.microsoft.com/security/business/siem-and-security-management/copilot",
        "features": [
            "Investigación automatizada de incidentes",
            "Enriquecimiento de alertas",
            "Generación de reportes",
            "Recomendaciones de respuesta",
        ],
    },
    "nvidia_morpheus": {
        "name": "NVIDIA Morpheus",
        "description": "Framework para procesamiento de seguridad en tiempo real",
        "link": "https://developer.nvidia.com/morpheus",
        "paper": "Augmenting Security Operations Centers with NVIDIA Morpheus (2024)",
        "authors": ["Katherine Huang", "Dhruv Nandakumar"],
        "features": [
            "Digital fingerprinting",
            "Detección de anomalías",
            "Generación de reportes con LLMs",
            "SOC copilot con NVIDIA NIM",
        ],
        "model": "Llama 3.1 para generación de reportes",
    },
    "palo_alto_prisma": {
        "name": "Palo Alto Networks Prisma AIRS",
        "description": "AI-driven incident management",
        "link": "https://www.paloaltonetworks.com/prisma/cloud/aiws",
        "features": [
            "ML para scoring de amenazas",
            "Automatización de respuesta",
            "Reducción de falsos positivos",
        ],
    },
}

# ============================================
# OFFENSIVE AI / AI RED TEAMING
# ============================================

OFFENSIVE_AI = {
    "adversarial_ml": {
        "description": "Ataques a sistemas de ML",
        "categories": {
            "poisoning": {
                "description": "Envenenamiento de datos de entrenamiento",
                "techniques": ["data injection", "label flipping", "backdoor attacks"],
                "defenses": ["anomaly detection", "data validation"],
            },
            "evasion": {
                "description": "Evasión de detectores en tiempo de inferencia",
                "techniques": ["FGSM", "PGD", "C&W", "adversarial patches"],
                "defenses": ["adversarial training", "certified defenses"],
            },
            "extraction": {
                "description": "Extracción de modelos",
                "techniques": ["model stealing", "membership inference", "model inversion"],
                "defenses": ["differential privacy", "output perturbation"],
            },
        },
    },
    "red_teaming_llms": {
        "description": "Red teaming para LLMs",
        "techniques": [
            "Prompt injection",
            "Jailbreaking",
            "Hallucination attacks",
            "Output manipulation",
            "Context manipulation",
        ],
        "frameworks": ["Microsoft Counterfit", "Google PAIR", "DeepMind Red Teaming"],
        "papers": [
            "Attack Atlas: Red Teaming GenAI (2024)",
            "A Survey on Offensive AI Within Cybersecurity (2024)",
        ],
    },
}

# ============================================
# AI DEFENSE / PROTEGER IA
# ============================================

AI_DEFENSE = {
    "glaze_nightshade": {
        "name": "Glaze & Nightshade",
        "description": "Protección de artistas contra robo de estilo por IA",
        "researchers": ["Ben Zhao", "Heather Zheng", "Shawn Shan"],
        "institution": "UChicago SAND Lab",
        "venue": "USENIX Security 2024",
        "link": "https://glaze.cs.uchicago.edu/",
        "purpose": "Proteger obras artísticas de ser usadas sin permiso para entrenar IA",
    },
    "datasentinel": {
        "name": "DataSentinel",
        "description": "Detección de prompt injection attacks",
        "researchers": ["Dawn Song", "Berkeley RDI Team"],
        "venue": "IEEE S&P 2025",
        "award": "Distinguished Paper Award",
        "purpose": "Detectar ataques de prompt injection en LLMs",
    },
    "nist_taxonomy": {
        "name": "NIST AI 100-2e2025",
        "description": "Taxonomía de Adversarial ML",
        "authors": ["Apostol Vassilev", "Alina Oprea", "Alie Fordyce", "Hyrum Anderson"],
        "link": "https://csrc.nist.gov/pubs/ai/100/2/e2025/final",
        "purpose": "Estándar industrial para clasificar ataques y defensas de ML",
    },
}

# ============================================
# PAPERS FUNDAMENTALES
# ============================================

AI_SECURITY_PAPERS = {
    "malware_detection": [
        {
            "title": "EMBER2024: Advancing Cybersecurity ML",
            "authors": ["Phil Roth", "Hyrum Anderson", "Edward Raff"],
            "year": 2025,
            "venue": "arXiv",
            "link": "https://arxiv.org/abs/2506.05074",
            "topic": "malware_detection",
        },
        {
            "title": "A Survey of Malware Detection Using Deep Learning",
            "authors": ["Ahmed Bensaoud", "Jugal Kalita"],
            "year": 2024,
            "venue": "arXiv",
            "link": "https://arxiv.org/abs/2407.19153",
            "topic": "malware_detection",
        },
        {
            "title": "ML-Based Behavioral Malware Detection Is Far From a Solved Problem",
            "authors": ["Researchers"],
            "year": 2024,
            "venue": "arXiv",
            "link": "https://arxiv.org/abs/2405.06124",
            "topic": "malware_detection",
        },
    ],
    "soc_automation": [
        {
            "title": "AI-Driven Guided Response for Security Operation Centers",
            "authors": ["Scott Freitas", "Jovan Kalajdjieski", "Amir Gharib", "Robert McCann"],
            "year": 2024,
            "venue": "arXiv",
            "impact": "30.13% reducción MTTR",
            "link": "https://arxiv.org/abs/2407.09017",
            "topic": "soc_automation",
        }
    ],
    "offensive_ai": [
        {
            "title": "Attack Atlas: A Practitioner Perspective on Red Teaming GenAI",
            "authors": ["Ambrish Rawat", "Stefan Schoepf", "Giulio Zizzo"],
            "year": 2024,
            "venue": "arXiv",
            "link": "https://arxiv.org/abs/2409.15398",
            "topic": "offensive_ai",
        },
        {
            "title": "A Survey on Offensive AI Within Cybersecurity",
            "authors": ["Sahil Girhepuje", "IIT Madras"],
            "year": 2024,
            "venue": "arXiv",
            "link": "https://arxiv.org/abs/2410.03566",
            "topic": "offensive_ai",
        },
    ],
    "adversarial_ml": [
        {
            "title": "Explaining and Harnessing Adversarial Examples",
            "authors": ["Ian Goodfellow", "Yoshua Bengio", "Aaron Courville"],
            "year": 2014,
            "venue": "ICLR",
            "citations": "100K+",
            "key_contribution": "Fast Gradient Sign Method (FGSM)",
            "link": "https://arxiv.org/abs/1412.6572",
            "topic": "adversarial_ml",
        },
        {
            "title": "Adversarial Examples Are Not Easily Detected",
            "authors": ["Nicholas Carlini", "David Wagner"],
            "year": 2017,
            "venue": "ACM AISec",
            "key_contribution": "Carlini-Wagner attacks (C&W)",
            "link": "https://nicholas.carlini.com/papers/2017_aisec_breakingdetection.pdf",
            "topic": "adversarial_ml",
        },
    ],
}

# ============================================
# HERRAMIENTAS Y DATASETS
# ============================================

AI_SECURITY_TOOLS = {
    "datasets": [
        {
            "name": "EMBER",
            "description": "Malware benchmark dataset",
            "link": "https://github.com/elastic/ember",
            "type": "benchmark",
        },
        {
            "name": "Microsoft Malware Classification",
            "description": "Kaggle competition dataset",
            "link": "https://www.kaggle.com/c/microsoft-malware-prediction",
            "type": "dataset",
        },
        {
            "name": "VirusTotal Collections",
            "description": "Samples para análisis",
            "link": "https://www.virustotal.com/",
            "type": "dataset",
        },
    ],
    "frameworks": [
        {
            "name": "Microsoft Copilot for Security",
            "type": "commercial",
            "description": "AI assistant para SOC",
        },
        {
            "name": "NVIDIA Morpheus",
            "type": "open_source",
            "description": "Framework para seguridad ML",
        },
        {
            "name": "Microsoft Counterfit",
            "type": "open_source",
            "description": "CLI para red teaming de ML",
            "link": "https://github.com/Azure/Counterfit",
        },
    ],
}


# ============================================
# FUNCIONES DE BÚSQUEDA
# ============================================


async def search_ai_security(query: str, format: str = "brief") -> str:
    """Busca recursos de IA Security."""
    query_lower = query.lower()
    results = []

    # Malware Detection
    if query_lower in ["malware_detection", "malware", "ember"]:
        if format == "brief":
            results.append(f"""**🛡️ Malware Detection con ML**

**EMBER Benchmark** (CrowdStrike)
- Link: https://github.com/elastic/ember
- Técnicas: Static + Dynamic + Hybrid analysis
- Models: Random Forest, XGBoost, LSTM, GNN

**Papers clave:**
- EMBER2024: A Benchmark Dataset for Holistic Evaluation
- Survey of Malware Detection Using Deep Learning (2024)""")
        elif format == "tools":
            results.append("**Herramientas:** EMBER, VirusTotal, Kaggle Microsoft Dataset")
        else:
            results.append(MALWARE_DETECTION["ember"])

    # SOC Automation
    elif query_lower in ["soc_automation", "soc", "automation"]:
        if format == "brief":
            results.append(f"""**🏢 AI para SOC Automation**

**Microsoft Copilot for Security**
- Impacto: 30.13% reducción MTTR
- Paper: Freitas et al. (2024)
- Link: https://www.microsoft.com/security

**NVIDIA Morpheus**
- Digital fingerprinting + LLM para reportes
- Paper: Huang & Nandakumar (2024)""")
        elif format == "citation":
            for paper in AI_SECURITY_PAPERS["soc_automation"]:
                results.append(
                    f"{paper['authors'][0]} et al. ({paper['year']}). {paper['title']}. {paper['venue']}."
                )
        else:
            results.append(SOC_AI_TOOLS)

    # Offensive AI
    elif query_lower in ["offensive_ai", "red_teaming", "attack"]:
        if format == "brief":
            results.append(f"""**⚔️ Offensive AI / Red Teaming**

**Técnicas:**
- Poisoning: Data injection, backdoors
- Evasion: FGSM, PGD, C&W attacks
- Extraction: Model stealing, membership inference

**Papers clave:**
- Attack Atlas: Red Teaming GenAI (2024)
- Survey on Offensive AI Within Cybersecurity (2024)

**Frameworks:**
- Microsoft Counterfit, Google PAIR""")
        else:
            results.append(OFFENSIVE_AI)

    # AI Defense
    elif query_lower in ["ai_defense", "defense", "protection"]:
        if format == "brief":
            results.append(f"""**🛡️ AI Defense**

**Glaze & Nightshade** (UChicago SAND Lab)
- Protege arte contra robo de estilo por IA
- Venue: USENIX Security 2024

**DataSentinel** (Dawn Song, IEEE S&P 2025)
- Detección de prompt injection
- Award: Distinguished Paper

**NIST AI 100-2e2025**
- Taxonomía de Adversarial ML""")
        else:
            results.append(AI_DEFENSE)

    # Adversarial ML
    elif query_lower in ["adversarial_ml", "adversarial", "aml"]:
        if format == "citation":
            for paper in AI_SECURITY_PAPERS["adversarial_ml"]:
                results.append(
                    f"{paper['authors'][0]} et al. ({paper['year']}). {paper['title']}. {paper['venue']}."
                )
        else:
            results.append(f"""**🎯 Adversarial ML**

**Papers fundamentales:**
1. Goodfellow et al. (2014): Explaining and Harnessing Adversarial Examples (FGSM)
2. Carlini & Wagner (2017): Adversarial Examples Are Not Easily Detected (C&W attacks)

**NIST AI 100-2e2025:**
- Ataques: Poisoning, Evasion, Inference
- Defensas: Adversarial training, Differential privacy""")

    else:
        return f"""❌ No se encontraron recursos para '{query}'.

**Topics disponibles:**
- malware_detection: EMBER, técnicas ML/DL
- soc_automation: Microsoft Copilot, NVIDIA Morpheus
- offensive_ai: Red Teaming, ataques adversarial
- ai_defense: Glaze, DataSentinel, NIST
- adversarial_ml: Papers fundamentales"""

    return "\n\n".join(results)


async def get_ai_paper(query: str, format: str = "brief") -> str:
    """Busca papers de IA Security."""
    query_lower = query.lower()
    results = []

    all_papers = (
        AI_SECURITY_PAPERS.get("malware_detection", [])
        + AI_SECURITY_PAPERS.get("soc_automation", [])
        + AI_SECURITY_PAPERS.get("offensive_ai", [])
        + AI_SECURITY_PAPERS.get("adversarial_ml", [])
    )

    for paper in all_papers:
        if (
            query_lower in paper.get("topic", "").lower()
            or query_lower in paper.get("title", "").lower()
        ):
            if format == "brief":
                results.append(f"""**{paper["title"]}**
- Autores: {", ".join(paper["authors"])}
- Año: {paper["year"]}
- Venue: {paper["venue"]}""")
            elif format == "citation":
                authors = ", ".join(paper["authors"][:2]) + (
                    " et al." if len(paper["authors"]) > 2 else ""
                )
                results.append(f"{authors} ({paper['year']}). {paper['title']}. {paper['venue']}.")
            else:
                results.append(f"""
**{paper["title"]}**
- Autores: {", ".join(paper["authors"])}
- Año: {paper["year"]}
- Venue: {paper["venue"]}
- Link: {paper["link"]}
- Topic: {paper.get("topic", "N/A")}
""")

    if not results:
        return f"❌ No se encontraron papers para '{query}'. Topics: malware_detection, soc_automation, offensive_ai, adversarial_ml"

    return "\n\n".join(results)
