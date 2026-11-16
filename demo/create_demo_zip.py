"""Gera o ZIP demonstrativo a partir dos exemplos deste diretório."""

from __future__ import annotations

import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "vibecheck-demo.zip"
FILES = (
    ("src/vulnerable_python.py", ROOT / "vulnerable_python.py"),
    ("src/vulnerable_javascript.js", ROOT / "vulnerable_javascript.js"),
    ("requirements.txt", ROOT / "requirements.txt"),
)


def main() -> None:
    with zipfile.ZipFile(OUTPUT, "w") as archive:
        for archive_name, source_path in FILES:
            info = zipfile.ZipInfo(archive_name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, source_path.read_bytes())
    print(f"ZIP demonstrativo gerado: {OUTPUT.name}")


if __name__ == "__main__":
    main()
