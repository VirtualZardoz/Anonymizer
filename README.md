# Anonymizer

Local document anonymization tool for confidential files before cloud LLM processing.

Replaces real names, addresses, financial data, and identifiers with consistent fake equivalents. Maintains a reversible mapping table so LLM output can be de-anonymized afterward.

## Why

Sending confidential client documents (legal, financial) to cloud LLMs constitutes a data breach. This tool anonymizes documents locally before they leave your machine, and reverses the anonymization on the results.

## How it works

Three-layer pipeline:

1. **Regex** — catches structured PII: emails, phones, IBAN, AHV/AVS, dates, amounts, postal codes, dossier references. Dates are shifted by a fixed offset, amounts scaled by a fixed factor (preserves timelines and proportions).

2. **GLiNER NER** — multilingual neural entity recognition (FR/DE/EN/ES/IT/PT). Catches person names, organizations, and addresses that regex can't. Runs locally on CPU, no cloud calls. Name variants (bare surnames, title-less forms) are automatically derived from detected entities.

3. **Verification** — checks the anonymized output for leaked PII using known entity lists, institution name matching, and optional Ollama LLM review.

All replacements are deterministic (hash-seeded Faker) — the same entity always maps to the same pseudonym within a vault.

## Quick start

### Web UI

Double-click `Anonymizer.bat` (Windows) or run:

```bash
python3 app.py
```

Opens a browser UI where you can create vaults, upload files, anonymize, preview results, and download.

### CLI

```bash
# Create a vault
python3 anonymize.py init my-case --locale fr_CH --password mypass

# Drop files into vaults/my-case/originals/

# Run anonymization
python3 anonymize.py run my-case --password mypass

# View the mapping table
python3 anonymize.py show-map my-case --password mypass

# De-anonymize LLM output
python3 deanonymize.py my-case ./output-files/ --password mypass
```

## Vault structure

```
vaults/my-case/
  originals/        ← your confidential files (never leaves this folder)
  mapping.enc       ← encrypted reversible key (never share this)
  anonymized/       ← safe .md files (share these with your LLM)
  deanonymized/     ← restored output after reverse mapping
  known_entities.json  ← (optional) entities to always anonymize
```

## Known entities

Create `vaults/{name}/known_entities.json` to force-anonymize specific entities:

```json
{
  "persons": ["John Smith"],
  "organizations": ["Lombard Odier", "BCGE"],
  "addresses": ["Rue du Rhône 42"]
}
```

## Encryption

When `--password` is provided, the mapping table is encrypted at rest using Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2 key derivation (480K iterations). Compliant with ENISA pseudonymization guidelines and GDPR Article 4(5).

## Dependencies

- Python 3.10+
- Faker — pseudonym generation
- GLiNER — multilingual NER
- cryptography — mapping table encryption
- Flask — web UI
- docling / pandoc — document conversion (.docx, .pdf → text)
- Ollama (optional) — Layer 3 LLM verification

```bash
pip install -r requirements.txt
```

## What it catches

| Category | Method | Example |
|----------|--------|---------|
| Person names | GLiNER + variants | Maître Jean-Pierre Fontaine → Nathan Barbey |
| Organizations | GLiNER + known list | UBS SA → Boechat Delèze Sàrl. SA |
| Addresses | GLiNER | Rue du Rhône 42 → avenue Camille Corbat 75 |
| Emails | Regex | jp.fontaine@firm.ch → elisarappaz@example.org |
| Phones | Regex | +41 22 310 45 67 → 0842 256 601 |
| IBAN | Regex | CH93 0015 2345... → CH48 5930 1699... |
| AHV/AVS | Regex | 756.1234.5678.97 → 756.1534.8600.47 |
| Dates | Regex + shift | 15 mars 2026 → 6 février 2026 |
| Amounts | Regex + scale | CHF 850'000.00 → CHF 1'164'500.00 |
| Postal codes | Regex | 1204 Genève → 9543 Barillon am Albis |
| Dossier refs | Regex | N° 2024/PHF-1847 → REF-001 |
