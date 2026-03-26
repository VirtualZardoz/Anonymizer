"""Layer 1: Regex-based PII detection for Swiss legal/financial documents."""

import re
from dataclasses import dataclass
from typing import List


@dataclass
class Detection:
    start: int
    end: int
    text: str
    entity_type: str
    source: str = "regex"


def detect_all(text: str, patterns: dict) -> List[Detection]:
    """Run all regex detectors on text. Returns non-overlapping detections sorted by position."""
    detections = []

    detections.extend(_detect_emails(text, patterns.get("email", "")))
    detections.extend(_detect_phones(text, patterns))
    detections.extend(_detect_ibans(text, patterns))
    detections.extend(_detect_ahv(text, patterns.get("ahv_avs", "")))
    detections.extend(_detect_dates(text, patterns))
    detections.extend(_detect_amounts(text, patterns.get("amount", "")))
    detections.extend(_detect_dossier_refs(text, patterns.get("dossier_ref", "")))
    detections.extend(_detect_swiss_postal(text, patterns.get("swiss_postal", "")))

    # Remove overlapping detections (keep the longest match)
    detections = _resolve_overlaps(detections)
    detections.sort(key=lambda d: d.start)
    return detections


def _detect_emails(text: str, pattern: str) -> List[Detection]:
    if not pattern:
        return []
    return [
        Detection(m.start(), m.end(), m.group(), "email")
        for m in re.finditer(pattern, text)
    ]


def _detect_phones(text: str, patterns: dict) -> List[Detection]:
    results = []
    for key in ("phone_ch", "phone_intl"):
        pattern = patterns.get(key, "")
        if pattern:
            for m in re.finditer(pattern, text):
                results.append(Detection(m.start(), m.end(), m.group(), "phone"))
    return results


def _detect_ibans(text: str, patterns: dict) -> List[Detection]:
    results = []
    for key in ("iban_ch", "iban_intl"):
        pattern = patterns.get(key, "")
        if pattern:
            for m in re.finditer(pattern, text):
                results.append(Detection(m.start(), m.end(), m.group(), "iban"))
    return results


def _detect_ahv(text: str, pattern: str) -> List[Detection]:
    if not pattern:
        return []
    return [
        Detection(m.start(), m.end(), m.group(), "ahv")
        for m in re.finditer(pattern, text)
    ]


def _detect_dates(text: str, patterns: dict) -> List[Detection]:
    results = []
    for key in ("date_euro", "date_iso", "date_written_fr", "date_written_en"):
        pattern = patterns.get(key, "")
        if pattern:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                results.append(Detection(m.start(), m.end(), m.group(), f"date_{key.split('_', 1)[1]}"))
    return results


def _detect_amounts(text: str, pattern: str) -> List[Detection]:
    if not pattern:
        return []
    results = []
    for m in re.finditer(pattern, text):
        # Skip if the match is just a bare number without currency indicator
        matched = m.group().strip()
        if re.search(r'[A-Za-z€$]', matched):
            results.append(Detection(m.start(), m.end(), m.group(), "amount"))
    return results


def _detect_dossier_refs(text: str, pattern: str) -> List[Detection]:
    if not pattern:
        return []
    return [
        Detection(m.start(), m.end(), m.group(), "dossier_ref")
        for m in re.finditer(pattern, text)
    ]


def _detect_swiss_postal(text: str, pattern: str) -> List[Detection]:
    if not pattern:
        return []
    return [
        Detection(m.start(), m.end(), m.group(), "postal_code")
        for m in re.finditer(pattern, text, re.MULTILINE)
    ]


def _resolve_overlaps(detections: List[Detection]) -> List[Detection]:
    """Remove overlapping detections, keeping the longest match."""
    if not detections:
        return []

    # Sort by start position, then by length (longest first)
    detections.sort(key=lambda d: (d.start, -(d.end - d.start)))

    resolved = [detections[0]]
    for det in detections[1:]:
        last = resolved[-1]
        if det.start >= last.end:
            resolved.append(det)
        elif (det.end - det.start) > (last.end - last.start):
            # Replace with longer match if it starts at the same place
            if det.start == last.start:
                resolved[-1] = det
    return resolved
