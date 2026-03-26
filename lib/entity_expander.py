"""Post-NER entity expansion: catches name variants and known entities.

Problem 1 — Name variants:
  GLiNER detects "Madame Céline Dubois-Marchand" but not bare "Dubois-Marchand"
  elsewhere in the text. This module extracts plausible sub-forms from detected
  person and organization names, then searches for unmatched occurrences.

Problem 2 — Known entities:
  Some entities (banks, firms, individuals) are known in advance for a vault.
  These are loaded from vaults/{name}/known_entities.json and always anonymized.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Set

from .detectors import Detection

# Titles to strip when extracting name variants (multilingual)
TITLES = {
    # French
    "maître", "maitre", "mme", "mme.", "madame", "m.", "monsieur",
    "dr", "dr.", "prof", "prof.", "me", "me.",
    # German
    "herr", "frau", "dr.", "prof.",
    # English
    "mr", "mr.", "mrs", "mrs.", "ms", "ms.", "dr", "dr.", "prof", "prof.",
    # Italian
    "sig", "sig.", "sig.ra", "dott", "dott.",
}


def expand_name_variants(
    text: str,
    detections: List[Detection],
    already_mapped: Set[str],
    mapping_entities: Dict[str, dict] = None,
) -> List[Detection]:
    """Generate variant detections for person and org names found by NER.

    For each person detection like "Madame Céline Dubois-Marchand", generates:
    - "Céline Dubois-Marchand" (without title)
    - "Dubois-Marchand" (surname only, if compound or multi-word)

    For each organization like "Banque Cantonale de Genève (BCGE)", generates:
    - "BCGE" (parenthetical abbreviation)

    Only returns variants that actually appear in the text and aren't already detected.

    Returns (detections, variant_replacements) where variant_replacements maps
    variant_text → derived replacement (from parent entity's replacement).
    """
    new_detections = []
    variant_replacements: Dict[str, str] = {}
    detected_spans = {(d.start, d.end) for d in detections}
    detected_texts = {d.text for d in detections} | already_mapped

    if mapping_entities is None:
        mapping_entities = {}

    for det in detections:
        if det.entity_type == "person":
            variants = _person_variants(det.text)
        elif det.entity_type == "organization":
            variants = _org_variants(det.text)
        else:
            continue

        # Look up parent replacement to derive variant replacements
        parent_replacement = None
        if det.text in mapping_entities:
            parent_replacement = mapping_entities[det.text].get("replacement")

        for variant in variants:
            if variant in detected_texts or len(variant) < 3:
                continue

            # Derive replacement from parent
            if parent_replacement and det.entity_type == "person":
                derived = _derive_person_variant_replacement(det.text, variant, parent_replacement)
                if derived:
                    variant_replacements[variant] = derived
            elif parent_replacement and det.entity_type == "organization":
                variant_replacements[variant] = parent_replacement

            # Find all occurrences of this variant in the text
            for m in re.finditer(re.escape(variant), text):
                span = (m.start(), m.end())
                if span not in detected_spans:
                    new_detections.append(Detection(
                        start=m.start(),
                        end=m.end(),
                        text=variant,
                        entity_type=det.entity_type,
                        source="variant",
                    ))
                    detected_spans.add(span)

            detected_texts.add(variant)

    return new_detections, variant_replacements


def _derive_person_variant_replacement(parent_text: str, variant_text: str, parent_replacement: str) -> str:
    """Derive a variant replacement from the parent's replacement.

    Examples:
        parent: "Madame Céline Dubois-Marchand" → "Yvette Corbat"
        variant: "Dubois-Marchand" → "Corbat" (surname from replacement)
        variant: "Céline Dubois-Marchand" → "Yvette Corbat" (full replacement)

        parent: "Maître Jean-Pierre Fontaine" → "Nathan Barbey"
        variant: "Fontaine" → "Barbey"
    """
    parent_words = parent_text.split()
    variant_words = variant_text.split()
    replacement_words = parent_replacement.split()

    # If variant is the full name without title, use full replacement
    parent_clean = [w for w in parent_words if w.lower().rstrip(".") not in TITLES and w.lower() not in TITLES]
    if variant_words == parent_clean:
        return parent_replacement

    # If variant is the surname (last word of the clean name)
    if len(variant_words) == 1 and len(replacement_words) >= 1:
        # Return the last word of the replacement (surname)
        return replacement_words[-1]

    # If variant is a compound surname (e.g., hyphenated)
    if len(variant_words) == 1 and "-" in variant_text and len(replacement_words) >= 1:
        return replacement_words[-1]

    return None


def _person_variants(name: str) -> List[str]:
    """Extract plausible sub-forms from a person name."""
    variants = []
    words = name.split()

    # Strip leading title
    clean_words = []
    skip_next = False
    for i, w in enumerate(words):
        if skip_next:
            skip_next = False
            continue
        if w.lower().rstrip(".") in TITLES or w.lower() in TITLES:
            continue
        clean_words.append(w)

    if not clean_words:
        return variants

    # Full name without title
    no_title = " ".join(clean_words)
    if no_title != name:
        variants.append(no_title)

    # Surname only (last word or hyphenated compound)
    if len(clean_words) >= 2:
        surname = clean_words[-1]
        # Check for hyphenated compound surnames
        if "-" in clean_words[-1]:
            variants.append(clean_words[-1])
        elif len(clean_words) >= 3 and "-" in clean_words[-2]:
            # "Dubois-Marchand" might be split across last two words
            variants.append(f"{clean_words[-2]} {clean_words[-1]}")
            variants.append(clean_words[-1])
        else:
            # Only add standalone surname if it's distinctive enough (>4 chars)
            if len(surname) > 4:
                variants.append(surname)

    return variants


def _org_variants(name: str) -> List[str]:
    """Extract abbreviations and short forms from organization names."""
    variants = []

    # Extract parenthetical abbreviation: "Banque Cantonale de Genève (BCGE)" → "BCGE"
    paren_match = re.search(r'\(([A-ZÀ-Ü]{2,})\)', name)
    if paren_match:
        variants.append(paren_match.group(1))

    # Extract the name before parenthetical
    if "(" in name:
        before_paren = name[:name.index("(")].strip()
        if before_paren != name:
            variants.append(before_paren)

    return variants


def detect_known_entities(
    text: str,
    vault_path: Path,
    already_mapped: Set[str],
) -> List[Detection]:
    """Detect entities from the vault's known_entities.json file.

    known_entities.json format:
    {
        "persons": ["Jean-Pierre Fontaine", "Céline Dubois-Marchand"],
        "organizations": ["UBS SA", "Lombard Odier", "BCGE"],
        "addresses": ["Rue du Rhône 42"]
    }
    """
    known_path = vault_path / "known_entities.json"
    if not known_path.exists():
        return []

    known = json.loads(known_path.read_text(encoding="utf-8"))
    detections = []
    detected_spans = set()

    type_map = {
        "persons": "person",
        "organizations": "organization",
        "addresses": "address",
    }

    for category, entity_type in type_map.items():
        entities = known.get(category, [])
        for entity_text in entities:
            if entity_text in already_mapped:
                continue

            for m in re.finditer(re.escape(entity_text), text):
                span = (m.start(), m.end())
                if span not in detected_spans:
                    detections.append(Detection(
                        start=m.start(),
                        end=m.end(),
                        text=entity_text,
                        entity_type=entity_type,
                        source="known",
                    ))
                    detected_spans.add(span)

    return detections
