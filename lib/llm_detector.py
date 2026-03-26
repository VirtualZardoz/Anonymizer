"""Layer 3: Ollama-based verification of anonymized text.

This module handles ONLY the verification pass (checking if PII leaked through).
Entity extraction (Layer 2) is now handled by ner_detector.py (GLiNER).
"""

import json
import sys
from typing import List, Optional

import requests

VERIFY_PROMPT = """You are a PII verification assistant. The following text has been anonymized — all real names, addresses, and identifiers should have been replaced with fake ones.

Review the text carefully. Does it contain any REAL person names, company names, or addresses that look like they refer to actual people, organizations, or places?

Signs of missed PII:
- Names that sound like real Swiss/French people or firms
- Addresses with real Swiss street names or cities
- Bank names, law firm names, or other specific organizations
- Government office names or specific institutions

If you find suspicious items, return a JSON array of objects:
- "text": the suspicious text
- "reason": why you think it might be real PII

If the text looks clean, return an empty array: []

Text to verify:
---
{text}
---

Return ONLY the JSON array, no other text."""


def check_ollama(endpoint: str) -> bool:
    """Check if Ollama is reachable."""
    try:
        r = requests.get(f"{endpoint}/api/tags", timeout=5)
        return r.status_code == 200
    except (requests.ConnectionError, requests.Timeout):
        return False


def verify_anonymization(text: str, endpoint: str, model: str, timeout: int = 60) -> Optional[List[dict]]:
    """Use local LLM to verify no real PII remains. Returns None if Ollama unavailable."""
    if not check_ollama(endpoint):
        return None

    try:
        response = requests.post(
            f"{endpoint}/api/generate",
            json={
                "model": model,
                "prompt": VERIFY_PROMPT.format(text=text[:8000]),
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 2000},
            },
            timeout=timeout,
        )
        response.raise_for_status()
        raw = response.json().get("response", "")
        findings = _parse_json_response(raw)

        if findings is None:
            print("  WARNING: LLM returned unparseable response for verification", file=sys.stderr)
            return []

        return findings

    except (requests.RequestException, KeyError, json.JSONDecodeError) as e:
        print(f"  WARNING: LLM verification failed: {e}", file=sys.stderr)
        return []


def _parse_json_response(raw: str) -> Optional[list]:
    """Extract a JSON array from LLM response, handling markdown code fences."""
    raw = raw.strip()
    # Strip markdown code fences
    if raw.startswith("```"):
        lines = raw.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        raw = "\n".join(lines).strip()

    # Find the JSON array
    start = raw.find("[")
    end = raw.rfind("]")
    if start == -1 or end == -1:
        return None

    try:
        return json.loads(raw[start:end + 1])
    except json.JSONDecodeError:
        return None
