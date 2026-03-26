#!/usr/bin/env python3
"""
Document De-Anonymizer — Reverse anonymization using mapping table.

Usage:
    python3 deanonymize.py <vault-name> <input-path> [--output-dir <dir>] [--password <pw>]

    input-path: a file or directory of .md files to de-anonymize
    Output goes to vaults/<vault-name>/deanonymized/ by default
"""

import argparse
import sys
from pathlib import Path

TOOL_DIR = Path(__file__).parent
VAULTS_DIR = TOOL_DIR / "vaults"


def deanonymize_text(text: str, reverse_map: dict, entities: dict) -> str:
    """Replace all pseudonyms with original values.

    Reverses in layer order: GLiNER/LLM entities first (they contain embedded
    regex replacements), then regex entities. Within each layer, longest-match-first.
    """
    # Split by detection layer
    layer2_entries = {}  # gliner, llm
    layer1_entries = {}  # regex

    for replacement, original in reverse_map.items():
        detected_by = entities.get(original, {}).get("detected_by", "regex")
        if detected_by in ("gliner", "llm"):
            layer2_entries[replacement] = original
        else:
            layer1_entries[replacement] = original

    # Pass 1: Undo Layer 2 (GLiNER/LLM) — these contain embedded Layer 1 replacements
    for replacement, original in sorted(layer2_entries.items(), key=lambda x: len(x[0]), reverse=True):
        text = text.replace(replacement, original)

    # Pass 2: Undo Layer 1 (regex) — clean up remaining regex-level replacements
    for replacement, original in sorted(layer1_entries.items(), key=lambda x: len(x[0]), reverse=True):
        text = text.replace(replacement, original)

    return text


def main():
    parser = argparse.ArgumentParser(description="De-anonymize documents using mapping table")
    parser.add_argument("vault_name", help="Vault whose mapping table to use")
    parser.add_argument("input_path", help="File or directory of .md files to de-anonymize")
    parser.add_argument("--output-dir", default=None, help="Output directory (default: vault's deanonymized/)")
    parser.add_argument("--password", default=None, help="Password for encrypted mapping table")

    args = parser.parse_args()

    vault_path = VAULTS_DIR / args.vault_name
    if not vault_path.exists():
        print(f"Vault '{args.vault_name}' not found.")
        sys.exit(1)

    # Load mapping table (handles encryption transparently)
    from lib.replacer import MappingTable
    mapping = MappingTable(vault_path, password=args.password)
    reverse_map = mapping.build_reverse_map()
    entities = mapping.entities

    if not reverse_map:
        print("Mapping table is empty — nothing to de-anonymize.")
        sys.exit(0)

    # Determine output directory
    output_dir = Path(args.output_dir) if args.output_dir else vault_path / "deanonymized"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Collect input files
    input_path = Path(args.input_path)
    if input_path.is_file():
        files = [input_path]
    elif input_path.is_dir():
        files = sorted(input_path.glob("*.md"))
    else:
        print(f"Input path not found: {input_path}")
        sys.exit(1)

    if not files:
        print(f"No .md files found in {input_path}")
        sys.exit(1)

    print(f"De-anonymizing {len(files)} file(s) using {len(reverse_map)} mappings")
    print(f"Output: {output_dir}/\n")

    for f in files:
        text = f.read_text(encoding="utf-8")
        restored = deanonymize_text(text, reverse_map, entities)
        output_path = output_dir / f.name
        output_path.write_text(restored, encoding="utf-8")
        print(f"  {f.name} → {output_path.name}")

    print(f"\nDone. {len(files)} file(s) de-anonymized.")


if __name__ == "__main__":
    main()
