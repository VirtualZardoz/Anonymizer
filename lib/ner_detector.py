"""Layer 2: GLiNER-based NER for contextual PII detection.

Replaces Ollama-based entity extraction with a deterministic, CPU-capable,
multilingual PII model. No truncation, no temperature randomness, <1s inference.
"""

import sys
from typing import List

from .detectors import Detection

# Lazy-loaded singleton — model is ~500MB, load once
_model = None
_model_name = None


def _get_model(model_name: str):
    global _model, _model_name
    if _model is None or _model_name != model_name:
        from gliner import GLiNER
        print(f"  Loading GLiNER model: {model_name}...", file=sys.stderr)
        _model = GLiNER.from_pretrained(model_name)
        _model_name = model_name
    return _model


def extract_entities(
    text: str,
    model_name: str = "urchade/gliner_multi_pii-v1",
    labels: list = None,
    threshold: float = 0.5,
) -> List[Detection]:
    """Extract PII entities using GLiNER. Deterministic, no truncation, CPU-capable."""
    if labels is None:
        labels = ["person", "organization", "full address"]

    model = _get_model(model_name)
    entities = model.predict_entities(text, labels, threshold=threshold)

    detections = []
    for ent in entities:
        detections.append(Detection(
            start=ent["start"],
            end=ent["end"],
            text=ent["text"],
            entity_type=_normalize_type(ent["label"]),
            source="gliner",
        ))

    return _deduplicate(detections)


def _normalize_type(label: str) -> str:
    """Map GLiNER labels to our entity types."""
    mapping = {
        "person": "person",
        "organization": "organization",
        "full address": "address",
        "street address": "address",
        "phone number": "phone",
        "email": "email",
        "date": "date",
        "credit card number": "credit_card",
        "passport number": "passport",
        "social security number": "ahv",
    }
    return mapping.get(label.lower(), label.lower())


def _deduplicate(detections: List[Detection]) -> List[Detection]:
    """Remove duplicate detections (same span, same type)."""
    seen = set()
    unique = []
    for det in detections:
        key = (det.start, det.end, det.entity_type)
        if key not in seen:
            seen.add(key)
            unique.append(det)
    return unique
