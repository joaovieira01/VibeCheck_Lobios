"""Mede a varredura de um repositório sintético com 500 arquivos."""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.repo_scan import scan_repository


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="vibecheck-bench-") as temporary:
        repository = Path(temporary)
        for index in range(500):
            extension = ".py" if index % 2 == 0 else ".ts"
            body = (
                f"# exemplo seguro {index}\nvalue = {index}\n"
                if extension == ".py"
                else f"// exemplo seguro {index}\nconst value = {index};\n"
            )
            (repository / f"arquivo_{index:03d}{extension}").write_text(
                body, encoding="utf-8"
            )

        started = time.perf_counter()
        report = scan_repository(repository)
        elapsed = time.perf_counter() - started

    print("Benchmark de repositório sintético")
    print(f"Arquivos analisados: {len(report['filesAnalyzed'])}/500")
    print(f"Achados: {sum(report['countsBySeverity'].values())}")
    print(f"Tempo medido: {elapsed:.3f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
