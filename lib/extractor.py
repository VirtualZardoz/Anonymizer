"""Document-to-text extraction using docling or pandoc fallback."""

import re
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

# Matches inline base64 images from docling output (e.g. ![Image](data:image/png;base64,...))
_BASE64_IMAGE_RE = re.compile(r'!\[[^\]]*\]\(data:image/[^)]+\)')

SUPPORTED_EXTENSIONS = {".docx", ".pdf", ".html", ".htm", ".txt", ".md", ".rtf", ".pptx", ".xlsx"}
PASSTHROUGH_EXTENSIONS = {".txt", ".md"}


def extract_file(file_path: Path) -> str:
    """Extract text content from a single file. Returns markdown text."""
    suffix = file_path.suffix.lower()

    if suffix not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file type: {suffix} ({file_path.name})")

    if suffix in PASSTHROUGH_EXTENSIONS:
        return file_path.read_text(encoding="utf-8")

    # Try docling first (best quality for .docx, .pdf)
    text = _try_docling(file_path)
    if text is not None:
        return _strip_base64_images(text)

    # Fallback to pandoc
    text = _try_pandoc(file_path)
    if text is not None:
        return text

    raise RuntimeError(f"Could not extract text from {file_path.name}. Neither docling nor pandoc succeeded.")


def extract_folder(folder_path: Path) -> List[Tuple[str, str]]:
    """Extract all supported files from a folder. Returns [(filename, text_content), ...]."""
    results = []
    files = sorted(f for f in folder_path.iterdir() if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS)

    if not files:
        print(f"  No supported files found in {folder_path}", file=sys.stderr)
        return results

    for f in files:
        print(f"  Extracting: {f.name}")
        try:
            text = extract_file(f)
            results.append((f.name, text))
        except Exception as e:
            print(f"  ERROR extracting {f.name}: {e}", file=sys.stderr)

    return results


def _strip_base64_images(text: str) -> str:
    """Remove inline base64 image data from docling output. Keeps text content only."""
    return _BASE64_IMAGE_RE.sub("", text)


def _try_docling(file_path: Path) -> str | None:
    """Try docling CLI for conversion."""
    try:
        abs_path = file_path.resolve()
        result = subprocess.run(
            ["docling", "--to", "md", str(abs_path)],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(abs_path.parent),
        )
        if result.returncode == 0:
            # docling writes output as <stem>.md in the same directory
            output_path = abs_path.parent / (abs_path.stem + ".md")
            if output_path.exists():
                text = output_path.read_text(encoding="utf-8")
                output_path.unlink()  # Clean up docling output
                return text
            # Sometimes docling writes to an output/ subdirectory
            output_dir = abs_path.parent / "output"
            if output_dir.exists():
                for md_file in output_dir.glob("*.md"):
                    text = md_file.read_text(encoding="utf-8")
                    md_file.unlink()
                    if output_dir.exists() and not any(output_dir.iterdir()):
                        output_dir.rmdir()
                    return text
        return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _try_pandoc(file_path: Path) -> str | None:
    """Try pandoc for conversion."""
    try:
        result = subprocess.run(
            ["pandoc", "-t", "markdown", "--wrap=none", str(file_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
        return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
