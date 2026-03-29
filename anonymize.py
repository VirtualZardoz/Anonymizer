#!/usr/bin/env python3
"""
Document Anonymizer — Local PII anonymization for confidential documents.

Usage:
    python3 anonymize.py init <vault-name> [--locale fr_CH] [--password <pw>]
    python3 anonymize.py run <vault-name> [--incremental] [--no-llm] [--password <pw>]
    python3 anonymize.py show-map <vault-name> [--password <pw>]
"""

import argparse
import json
import sys
from pathlib import Path

TOOL_DIR = Path(__file__).parent
VAULTS_DIR = TOOL_DIR / "vaults"
CONFIG_PATH = TOOL_DIR / "config" / "default.json"


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def cmd_init(args):
    """Create a new vault with directory structure."""
    vault_path = VAULTS_DIR / args.vault_name
    if vault_path.exists():
        print(f"Vault '{args.vault_name}' already exists at {vault_path}")
        sys.exit(1)

    for subdir in ("originals", "anonymized", "deanonymized"):
        (vault_path / subdir).mkdir(parents=True)

    # Initialize mapping table
    from lib.replacer import MappingTable
    config = load_config()
    locale = args.locale or config.get("locale", "fr_CH")
    mapping = MappingTable(vault_path, locale=locale, password=args.password)
    mapping.save()

    print(f"Vault created: {vault_path}")
    print(f"  Locale: {locale}")
    print(f"  Date offset: {mapping.date_offset:+d} days")
    print(f"  Amount factor: {mapping.amount_factor:.2f}x")
    if args.password:
        print(f"  Encryption: enabled (mapping.enc)")
    print(f"\nNext: drop confidential files into {vault_path / 'originals'}/")
    print(f"Then: python3 anonymize.py run {args.vault_name}")


def cmd_run(args):
    """Run the anonymization pipeline on a vault."""
    from lib.detectors import detect_all
    from lib.extractor import extract_folder
    from lib.llm_detector import check_ollama
    from lib.replacer import MappingTable, apply_replacements
    from lib.verifier import verify

    vault_path = VAULTS_DIR / args.vault_name
    if not vault_path.exists():
        print(f"Vault '{args.vault_name}' not found. Run 'init' first.")
        sys.exit(1)

    config = load_config()
    originals_dir = vault_path / "originals"
    anonymized_dir = vault_path / "anonymized"

    # Load mapping table
    mapping = MappingTable(vault_path, locale=config.get("locale", "fr_CH"), password=args.password)

    # Check which files to process
    already_processed = set(mapping.data.get("files_processed", []))

    # Step 1: Extract text from documents
    print("=== Step 1: Document Extraction ===")
    documents = extract_folder(originals_dir)
    if not documents:
        print("No documents to process.")
        return

    if args.incremental:
        documents = [(name, text) for name, text in documents if name not in already_processed]
        if not documents:
            print("All files already processed (use without --incremental to reprocess).")
            return
        print(f"  Incremental mode: {len(documents)} new file(s)")

    # Check GLiNER and Ollama availability
    gliner_available = not args.no_llm
    ollama_config = config.get("ollama", {})
    ollama_available = False
    if not args.no_llm:
        ollama_available = check_ollama(ollama_config.get("endpoint", "http://localhost:11434"))

    if args.no_llm:
        print("\n  Mode: regex-only (--no-llm)")
    else:
        gliner_config = config.get("gliner", {})
        print(f"\n  GLiNER: {gliner_config.get('model', 'urchade/gliner_multi_pii-v1')}")
        if ollama_available:
            print(f"  Ollama: connected ({ollama_config.get('model', 'qwen3:14b')}) — used for verification")
        else:
            print("  Ollama: not reachable — Layer 3 LLM verification will use regex fallback only")

    all_findings = []

    for filename, text in documents:
        print(f"\n=== Processing: {filename} ===")

        # Auto-detect document language for locale-appropriate replacements
        mapping.set_document_locale(text)
        if mapping._current_doc_locale != mapping.locale:
            print(f"  Language detected: {mapping._current_doc_locale} (default: {mapping.locale})")

        # Step 2: Layer 1 — Regex detection
        print("  Layer 1: Regex detection...")
        detections = detect_all(text, config.get("regex_patterns", {}))
        print(f"    Found {len(detections)} entities")
        for det in detections:
            print(f"    [{det.entity_type}] {det.text[:50]}{'...' if len(det.text) > 50 else ''}")

        # Apply Layer 1 replacements
        anonymized_text = apply_replacements(text, detections, mapping)

        # Step 3: Layer 2 — GLiNER NER (on partially anonymized text)
        if gliner_available:
            print("  Layer 2: GLiNER NER...")
            try:
                from lib.ner_detector import extract_entities as gliner_extract
                gliner_config = config.get("gliner", {})
                gliner_detections = gliner_extract(
                    anonymized_text,
                    model_name=gliner_config.get("model", "urchade/gliner_multi_pii-v1"),
                    labels=gliner_config.get("labels", ["person", "organization", "full address"]),
                    threshold=gliner_config.get("threshold", 0.5),
                )
                if gliner_detections:
                    print(f"    Found {len(gliner_detections)} additional entities")
                    for det in gliner_detections:
                        print(f"    [{det.entity_type}] {det.text[:50]}{'...' if len(det.text) > 50 else ''}")
                    anonymized_text = apply_replacements(anonymized_text, gliner_detections, mapping)
                else:
                    print("    No additional entities found")
            except Exception as e:
                print(f"    WARNING: GLiNER failed: {e}", file=sys.stderr)
                gliner_available = False
        else:
            print("  Layer 2: Skipped (--no-llm)")

        # Step 3b: Name variant expansion + known entities
        from lib.entity_expander import expand_name_variants, detect_known_entities
        already_mapped = set(mapping.entities.keys())

        # Expand name variants from all detections (catches "Dubois-Marchand" from "Madame Céline Dubois-Marchand")
        gliner_dets = gliner_detections if (gliner_available and 'gliner_detections' in locals()) else []
        all_prior_detections = detections + gliner_dets
        variant_detections, variant_replacements = expand_name_variants(
            anonymized_text, all_prior_detections, already_mapped, mapping.entities,
        )
        if variant_detections:
            print(f"  Layer 2b: Name variants — {len(variant_detections)} found")
            # Only register variants that were actually found in the text
            detected_variant_texts = {det.text for det in variant_detections}
            for variant_text, derived_repl in variant_replacements.items():
                if variant_text in detected_variant_texts and variant_text not in mapping.entities:
                    mapping.entities[variant_text] = {
                        "type": "person",
                        "replacement": derived_repl,
                        "detected_by": "variant",
                    }
            for det in variant_detections:
                repl = variant_replacements.get(det.text, det.text)
                print(f"    [{det.entity_type}] {det.text[:40]} → {repl[:40]}")
            anonymized_text = apply_replacements(anonymized_text, variant_detections, mapping)

        # Known entities (vault-specific always-anonymize list)
        already_mapped = set(mapping.entities.keys())
        known_detections = detect_known_entities(anonymized_text, vault_path, already_mapped)
        if known_detections:
            print(f"  Layer 2c: Known entities — {len(known_detections)} found")
            for det in known_detections:
                print(f"    [{det.entity_type}] {det.text[:50]}{'...' if len(det.text) > 50 else ''}")
            anonymized_text = apply_replacements(anonymized_text, known_detections, mapping)

        # Step 4: Layer 3 — Verification
        print("  Layer 3: Verification...")
        findings = verify(
            anonymized_text,
            mapping.entities,
            config.get("verification_known_banks", []),
            config.get("verification_known_cities", []),
            ollama_endpoint=ollama_config.get("endpoint", "") if ollama_available else "",
            ollama_model=ollama_config.get("model", ""),
            ollama_timeout=ollama_config.get("timeout_seconds", 60),
        )

        if findings:
            print(f"    {len(findings)} finding(s):")
            for f in findings:
                severity = f.get("severity", "?")
                icon = {"critical": "!!!", "warning": " ! ", "info": " i "}.get(severity, " ? ")
                print(f"    [{icon}] {f['text']}: {f['reason']}")
            all_findings.extend([(filename, f) for f in findings])
        else:
            print("    Clean — no leaks detected")

        # Write anonymized output
        output_stem = Path(filename).stem
        output_path = anonymized_dir / f"{output_stem}.md"
        output_path.write_text(anonymized_text, encoding="utf-8")
        print(f"  Written: {output_path.name}")

        # Track processed files
        if filename not in already_processed:
            mapping.data.setdefault("files_processed", []).append(filename)

    # Save mapping table
    mapping.save()

    # Summary
    print(f"\n{'=' * 60}")
    print(f"SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Files processed: {len(documents)}")
    print(f"  Entities mapped: {len(mapping.entities)}")
    print(f"  Verification findings: {len(all_findings)}")
    if args.no_llm:
        print(f"  Mode: regex-only")
    elif not gliner_available:
        print(f"  Mode: regex-only (GLiNER failed to load)")
    print(f"  Encryption: {'enabled' if args.password else 'disabled'}")
    print(f"\n  Anonymized files: {anonymized_dir}/")
    print(f"  Mapping table: {mapping.path}")

    if any(f[1].get("severity") == "critical" for f in all_findings):
        print(f"\n  CRITICAL: Some original entities still present in output!")
        print(f"  Review the findings above before using the anonymized files.")
        sys.exit(2)


def cmd_show_map(args):
    """Display the mapping table for a vault."""
    from lib.replacer import MappingTable

    vault_path = VAULTS_DIR / args.vault_name
    if not vault_path.exists():
        print(f"Vault '{args.vault_name}' not found.")
        sys.exit(1)

    mapping = MappingTable(vault_path, password=args.password)
    data = mapping.data
    settings = data.get("settings", {})
    entities = data.get("entities", {})

    print(f"Vault: {args.vault_name}")
    print(f"Created: {data.get('created', '?')}")
    print(f"Date offset: {settings.get('date_offset_days', '?'):+d} days")
    print(f"Amount factor: {settings.get('amount_factor', '?'):.2f}x")
    print(f"Locale: {settings.get('locale', '?')}")
    print(f"Files processed: {len(data.get('files_processed', []))}")
    print(f"Encryption: {'enabled' if args.password else 'disabled'}")
    print(f"\nEntities ({len(entities)}):")
    print(f"{'─' * 80}")

    # Group by type
    by_type = {}
    for original, info in entities.items():
        t = info["type"]
        by_type.setdefault(t, []).append((original, info))

    for entity_type, items in sorted(by_type.items()):
        print(f"\n  [{entity_type.upper()}]")
        for original, info in items:
            replacement = info["replacement"]
            detected = info.get("detected_by", "?")
            print(f"    {original[:35]:35s} → {replacement[:35]:35s} ({detected})")


def main():
    parser = argparse.ArgumentParser(description="Document Anonymizer — Local PII anonymization")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = subparsers.add_parser("init", help="Create a new vault")
    p_init.add_argument("vault_name", help="Name for the vault (e.g., pension-house)")
    p_init.add_argument("--locale", default=None, help="Faker locale (default: fr_CH)")
    p_init.add_argument("--password", default=None, help="Encrypt mapping table with this password")

    # run
    p_run = subparsers.add_parser("run", help="Run anonymization pipeline")
    p_run.add_argument("vault_name", help="Vault to process")
    p_run.add_argument("--incremental", action="store_true", help="Only process new files")
    p_run.add_argument("--no-llm", action="store_true", help="Skip GLiNER and Ollama (regex only)")
    p_run.add_argument("--password", default=None, help="Password for encrypted mapping table")

    # show-map
    p_map = subparsers.add_parser("show-map", help="Display mapping table")
    p_map.add_argument("vault_name", help="Vault to inspect")
    p_map.add_argument("--password", default=None, help="Password for encrypted mapping table")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "run":
        cmd_run(args)
    elif args.command == "show-map":
        cmd_show_map(args)


if __name__ == "__main__":
    main()
