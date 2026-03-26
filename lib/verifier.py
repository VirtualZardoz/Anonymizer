"""Layer 3: Verification — checks anonymized text for leaked PII."""

import re
import sys
from typing import Dict, List

from .llm_detector import verify_anonymization


def verify(
    text: str,
    mapping_entities: Dict[str, dict],
    known_banks: List[str],
    known_cities: List[str],
    ollama_endpoint: str = "",
    ollama_model: str = "",
    ollama_timeout: int = 60,
) -> List[dict]:
    """Verify anonymized text for PII leaks. Returns list of findings."""
    findings = []

    # Check 1: No original entities should appear in the anonymized text
    for original, info in mapping_entities.items():
        if original in text:
            findings.append({
                "text": original,
                "reason": f"Original {info['type']} entity still present in anonymized text",
                "severity": "critical",
                "source": "mapping_check",
            })

    # Check 2: Known institution names (regex fallback for when LLM is unavailable)
    for bank in known_banks:
        if re.search(r'\b' + re.escape(bank) + r'\b', text):
            # Check it's not part of a replacement
            is_replacement = any(bank in v["replacement"] for v in mapping_entities.values())
            if not is_replacement:
                findings.append({
                    "text": bank,
                    "reason": f"Known financial institution name found",
                    "severity": "warning",
                    "source": "known_banks",
                })

    # Check 3: Swiss city names that weren't part of postal code replacements
    replacement_cities = set()
    for v in mapping_entities.values():
        if v["type"] == "postal_code":
            replacement_cities.add(v["replacement"].split(maxsplit=1)[-1] if " " in v["replacement"] else "")

    for city in known_cities:
        if re.search(r'\b' + re.escape(city) + r'\b', text):
            if city not in replacement_cities:
                findings.append({
                    "text": city,
                    "reason": f"Known Swiss city name found (may be contextual, not PII)",
                    "severity": "info",
                    "source": "known_cities",
                })

    # Check 4: LLM verification (if available)
    if ollama_endpoint:
        llm_findings = verify_anonymization(text, ollama_endpoint, ollama_model, ollama_timeout)
        if llm_findings is not None:
            for f in llm_findings:
                findings.append({
                    "text": f.get("text", "?"),
                    "reason": f.get("reason", "LLM flagged as potential PII"),
                    "severity": "warning",
                    "source": "llm_verification",
                })
        elif llm_findings is None:
            print("  INFO: LLM verification skipped (Ollama unavailable)", file=sys.stderr)

    return findings
