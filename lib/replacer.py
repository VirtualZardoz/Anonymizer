"""Deterministic replacement engine using Faker for consistent pseudonym generation."""

import base64
import hashlib
import json
import os
import random
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

from faker import Faker


class MappingTable:
    """Manages the bidirectional mapping between real and anonymized entities.

    Supports optional password-based encryption (Fernet + PBKDF2).
    When password is provided, mapping is stored as mapping.enc (encrypted).
    When not provided, mapping is stored as mapping.json (plaintext, backward compat).
    """

    # Language detection → Faker locale mapping
    LANG_TO_LOCALE = {
        "fr": "fr_CH", "de": "de_CH", "en": "en_US", "it": "it_CH",
        "es": "es_ES", "pt": "pt_BR",
    }

    def __init__(self, vault_path: Path, locale: str = "fr_CH", password: str = None):
        self.vault_path = vault_path
        self.enc_path = vault_path / "mapping.enc"
        self.json_path = vault_path / "mapping.json"
        self.password = password
        self.locale = locale
        self.faker = Faker(locale)
        self._fakers: Dict[str, Faker] = {locale: self.faker}
        self._current_doc_locale: Optional[str] = None
        self.data: Dict[str, Any] = {}
        self._load()

    @property
    def path(self) -> Path:
        """Return the active mapping file path."""
        if self.password:
            return self.enc_path
        return self.json_path

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive a Fernet key from password + salt using PBKDF2."""
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
        return base64.urlsafe_b64encode(kdf.derive(self.password.encode()))

    def _load(self):
        # Try encrypted file first (if password provided)
        if self.enc_path.exists() and self.password:
            self._load_encrypted()
            return

        # Encrypted file exists but no password
        if self.enc_path.exists() and not self.password:
            print("ERROR: Vault has encrypted mapping (mapping.enc) but no --password provided.", file=sys.stderr)
            sys.exit(1)

        # Try plaintext file
        if self.json_path.exists():
            self.data = json.loads(self.json_path.read_text(encoding="utf-8"))
            return

        # Fresh vault — initialize
        self._init_fresh()

    def _load_encrypted(self):
        """Load and decrypt mapping.enc."""
        from cryptography.fernet import Fernet, InvalidToken
        raw = self.enc_path.read_bytes()
        salt, token = raw[:16], raw[16:]
        key = self._derive_key(salt)
        try:
            decrypted = Fernet(key).decrypt(token)
            self.data = json.loads(decrypted)
        except InvalidToken:
            print("ERROR: Wrong password — could not decrypt mapping table.", file=sys.stderr)
            sys.exit(1)

    def _init_fresh(self):
        """Create a fresh mapping table for a new vault."""
        self.data = {
            "version": "1.0",
            "created": datetime.now().isoformat(),
            "vault": self.vault_path.name,
            "settings": {
                "date_offset_days": random.randint(30, 90) * random.choice([-1, 1]),
                "amount_factor": round(random.uniform(0.7, 1.4), 2),
                "locale": self.locale,
            },
            "entities": {},
            "files_processed": [],
        }

    def save(self):
        if self.password:
            self._save_encrypted()
        else:
            self.json_path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")

    def _save_encrypted(self):
        """Encrypt and save mapping table."""
        from cryptography.fernet import Fernet
        salt = os.urandom(16)
        key = self._derive_key(salt)
        plaintext = json.dumps(self.data, ensure_ascii=False).encode("utf-8")
        token = Fernet(key).encrypt(plaintext)
        self.enc_path.write_bytes(salt + token)
        # Migrate: remove plaintext if it exists
        if self.json_path.exists():
            self.json_path.unlink()
            print("  Mapping table migrated to encrypted format.")

    def set_document_locale(self, text: str):
        """Auto-detect document language and set the active Faker locale."""
        try:
            from langdetect import detect
            lang = detect(text)
        except Exception:
            lang = None
        locale = self.LANG_TO_LOCALE.get(lang, self.locale)
        self._current_doc_locale = locale
        if locale not in self._fakers:
            self._fakers[locale] = Faker(locale)

    def _active_faker(self) -> Faker:
        """Return the Faker instance for the current document's detected language."""
        locale = self._current_doc_locale or self.locale
        return self._fakers.get(locale, self.faker)

    @property
    def entities(self) -> Dict[str, Dict]:
        return self.data["entities"]

    @property
    def date_offset(self) -> int:
        return self.data["settings"]["date_offset_days"]

    @property
    def amount_factor(self) -> float:
        return self.data["settings"]["amount_factor"]

    def get_replacement(self, original: str, entity_type: str, detected_by: str = "regex") -> str:
        """Get or create a consistent replacement for an entity."""
        if original in self.entities:
            return self.entities[original]["replacement"]

        replacement = self._generate_replacement(original, entity_type)
        self.entities[original] = {
            "type": entity_type,
            "replacement": replacement,
            "detected_by": detected_by,
        }
        return replacement

    def _generate_replacement(self, original: str, entity_type: str) -> str:
        """Generate a plausible replacement based on entity type."""
        faker = self._active_faker()
        # Seed faker for this specific entity so it's deterministic
        seed = int(hashlib.sha256(original.encode()).hexdigest()[:8], 16)
        faker.seed_instance(seed)

        if entity_type == "person":
            return faker.name()
        elif entity_type == "organization":
            return self._fake_org(original, faker)
        elif entity_type == "address":
            return f"{faker.street_address()}"
        elif entity_type == "email":
            return faker.email()
        elif entity_type == "phone":
            return faker.phone_number()
        elif entity_type == "iban":
            return self._fake_iban()
        elif entity_type == "ahv":
            return self._fake_ahv()
        elif entity_type == "postal_code":
            return self._fake_postal(faker)
        elif entity_type.startswith("date_"):
            return self._shift_date(original, entity_type)
        elif entity_type == "amount":
            return self._scale_amount(original)
        elif entity_type == "dossier_ref":
            count = sum(1 for e in self.entities.values() if e["type"] == "dossier_ref")
            return f"REF-{count + 1:03d}"
        else:
            return f"[REDACTED-{entity_type.upper()}]"

    def _fake_org(self, original: str, faker: Faker = None) -> str:
        """Generate a plausible Swiss organization name."""
        faker = faker or self._active_faker()
        # Preserve legal suffixes
        suffixes = ["SA", "Sàrl", "AG", "GmbH", "& Cie", "S.A."]
        found_suffix = ""
        for s in suffixes:
            if s in original:
                found_suffix = f" {s}"
                break
        return f"{faker.company()}{found_suffix}"

    def _fake_iban(self) -> str:
        """Generate a fake but plausible-format Swiss IBAN."""
        return f"CH{random.randint(10, 99)} {random.randint(1000, 9999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)} {random.randint(0, 9)}"

    def _fake_ahv(self) -> str:
        """Generate a fake AHV/AVS number."""
        return f"756.{random.randint(1000, 9999)}.{random.randint(1000, 9999)}.{random.randint(10, 99)}"

    def _fake_postal(self, faker: Faker = None) -> str:
        """Generate a fake Swiss postal code + city."""
        faker = faker or self._active_faker()
        return f"{faker.postcode()} {faker.city()}"

    def _shift_date(self, original: str, date_type: str) -> str:
        """Shift a date by the vault's fixed offset."""
        offset = timedelta(days=self.date_offset)

        try:
            if "euro" in date_type:
                # dd.mm.yyyy or dd/mm/yyyy
                sep = "." if "." in original else "/"
                parts = re.split(r'[./]', original)
                dt = datetime(int(parts[2]), int(parts[1]), int(parts[0]))
                shifted = dt + offset
                return shifted.strftime(f"%d{sep}%m{sep}%Y")

            elif "iso" in date_type:
                dt = datetime.strptime(original, "%Y-%m-%d")
                shifted = dt + offset
                return shifted.strftime("%Y-%m-%d")

            elif "written_fr" in date_type:
                months_fr = {
                    "janvier": 1, "février": 2, "mars": 3, "avril": 4,
                    "mai": 5, "juin": 6, "juillet": 7, "août": 8,
                    "septembre": 9, "octobre": 10, "novembre": 11, "décembre": 12,
                }
                months_fr_rev = {v: k for k, v in months_fr.items()}
                m = re.match(r'(\d{1,2})\s+(\w+)\s+(\d{4})', original)
                if m:
                    day, month_name, year = int(m.group(1)), m.group(2).lower(), int(m.group(3))
                    dt = datetime(year, months_fr[month_name], day)
                    shifted = dt + offset
                    return f"{shifted.day} {months_fr_rev[shifted.month]} {shifted.year}"

            elif "written_en" in date_type:
                # Try common English date formats
                for fmt in ("%B %d, %Y", "%B %d %Y"):
                    try:
                        dt = datetime.strptime(original, fmt)
                        shifted = dt + offset
                        return shifted.strftime("%B %d, %Y")
                    except ValueError:
                        continue

        except (ValueError, KeyError):
            pass

        # Fallback: return as-is with a marker
        return f"[DATE-SHIFT-FAILED:{original}]"

    def _scale_amount(self, original: str) -> str:
        """Scale a financial amount by the vault's fixed factor."""
        # Extract the numeric part
        numeric = re.findall(r"[\d',]+(?:\.\d{2})?", original)
        if not numeric:
            return original

        num_str = numeric[0].replace("'", "").replace(",", "")
        try:
            value = float(num_str)
            scaled = value * self.amount_factor
            # Format with Swiss thousands separator
            if "." in num_str:
                formatted = f"{scaled:,.2f}".replace(",", "'")
            else:
                formatted = f"{int(scaled):,}".replace(",", "'")
            # Replace the numeric part in the original string
            return original.replace(numeric[0], formatted)
        except ValueError:
            return original

    def build_reverse_map(self) -> Dict[str, str]:
        """Build replacement → original mapping for de-anonymization."""
        return {v["replacement"]: k for k, v in self.entities.items()}


def apply_replacements(text: str, detections: list, mapping: MappingTable) -> str:
    """Apply replacements to text based on detections. Works right-to-left to preserve positions."""
    # Sort by position, right-to-left
    sorted_dets = sorted(detections, key=lambda d: d.start, reverse=True)

    for det in sorted_dets:
        replacement = mapping.get_replacement(det.text, det.entity_type, det.source)
        text = text[:det.start] + replacement + text[det.end:]

    return text
