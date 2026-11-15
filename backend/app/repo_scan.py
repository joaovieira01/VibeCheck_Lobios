"""Varredura estática agregada de diretórios e arquivos ZIP."""

from __future__ import annotations

import math
import os
import stat
import struct
import tempfile
import time
import zlib
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from app.scanner import SEVERITY_ORDER, ScanTimeout, scan_source

MAX_FILE_BYTES = 1_000_000
MAX_ZIP_BYTES = 50 * 1_000_000
MAX_ZIP_FILES = 2_000
MAX_ZIP_ENTRIES = MAX_ZIP_FILES * 2
MAX_ZIP_ARCHIVE_BYTES = MAX_ZIP_BYTES + MAX_ZIP_FILES * 1_024
IGNORED_DIRECTORIES = {
    "node_modules",
    ".git",
    "dist",
    "build",
    "venv",
    ".venv",
    "__pycache__",
    "bin",
}
SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".php",
    ".java",
    ".go",
    ".rb",
    ".cs",
    ".c",
    ".cpp",
}


class RepositoryScanError(ValueError):
    """Entrada de repositório inválida ou arquivo compactado inseguro."""


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _supported(path: Path) -> bool:
    return path.name.casefold() == "requirements.txt" or (
        path.suffix.casefold() in SUPPORTED_EXTENSIONS
    )


def _discover(root: Path) -> tuple[list[Path], list[dict[str, str]]]:
    candidates: list[Path] = []
    ignored: list[dict[str, str]] = []

    def on_walk_error(error: OSError) -> None:
        failed_path = Path(error.filename) if error.filename else root
        try:
            relative = _relative(failed_path, root)
        except ValueError:
            relative = "."
        ignored.append({"path": relative, "reason": "diretório inacessível"})

    for current, dirs, files in os.walk(
        root, topdown=True, followlinks=False, onerror=on_walk_error
    ):
        current_path = Path(current)
        kept: list[str] = []
        for name in sorted(dirs, key=str.casefold):
            path = current_path / name
            if name.casefold() in IGNORED_DIRECTORIES:
                ignored.append(
                    {"path": _relative(path, root), "reason": "diretório ignorado"}
                )
            elif path.is_symlink():
                ignored.append(
                    {"path": _relative(path, root), "reason": "link simbólico"}
                )
            else:
                kept.append(name)
        dirs[:] = kept
        for name in sorted(files, key=str.casefold):
            path = current_path / name
            relative = _relative(path, root)
            if path.is_symlink():
                ignored.append({"path": relative, "reason": "link simbólico"})
            elif not _supported(path):
                ignored.append({"path": relative, "reason": "extensão não suportada"})
            else:
                candidates.append(path)
    candidates.sort(key=lambda item: _relative(item, root).casefold())
    return candidates, ignored


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data or any(
        byte < 9 or 13 < byte < 32 for byte in data
    )


def _scan_directory(
    root: Path,
    *,
    time_budget_seconds: float,
    started: float,
    ignored: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    candidates, discovered_ignored = _discover(root)
    ignored_files = [*(ignored or []), *discovered_ignored]
    deadline = started + time_budget_seconds
    findings_by_file: dict[str, list[dict[str, Any]]] = {}
    analyzed: list[str] = []
    not_analyzed: list[str] = []
    severity_counts: dict[str, int] = {}
    owasp_counts: dict[str, int] = {}

    for index, path in enumerate(candidates):
        relative = _relative(path, root)
        if time.perf_counter() >= deadline:
            not_analyzed.extend(_relative(item, root) for item in candidates[index:])
            break
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                ignored_files.append({"path": relative, "reason": "arquivo acima de 1 MB"})
                continue
            with path.open("rb") as source_file:
                data = source_file.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES:
                ignored_files.append({"path": relative, "reason": "arquivo acima de 1 MB"})
                continue
            if _is_binary(data):
                ignored_files.append({"path": relative, "reason": "arquivo binário"})
                continue
            source = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            ignored_files.append({"path": relative, "reason": "codificação não suportada"})
            continue
        except OSError:
            ignored_files.append({"path": relative, "reason": "arquivo inacessível"})
            continue

        remaining = max(0.0, deadline - time.perf_counter())
        try:
            result = scan_source(
                source,
                path.name,
                time_budget_seconds=remaining,
            )
        except ScanTimeout:
            not_analyzed.extend(_relative(item, root) for item in candidates[index:])
            break

        analyzed.append(relative)
        serialized = [finding.to_dict() for finding in result.findings]
        if serialized:
            findings_by_file[relative] = serialized
        for finding in result.findings:
            occurrence_count = len(finding.locations)
            severity_counts[finding.severity] = (
                severity_counts.get(finding.severity, 0) + occurrence_count
            )
            category = f"{finding.owasp_id} - {finding.owasp_name}"
            owasp_counts[category] = owasp_counts.get(category, 0) + occurrence_count

    return {
        "findingsByFile": findings_by_file,
        "countsBySeverity": severity_counts,
        "countsByOwasp": owasp_counts,
        "filesAnalyzed": analyzed,
        "ignoredFiles": ignored_files,
        "filesNotAnalyzed": not_analyzed,
        "partial": bool(not_analyzed),
        "durationSeconds": round(time.perf_counter() - started, 6),
    }


def _zip_entry_path(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    posix = PurePosixPath(normalized)
    windows = PureWindowsPath(name)
    if (
        "\x00" in name
        or posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or not posix.parts
        or any(part == ".." for part in posix.parts)
        or any(":" in part for part in posix.parts)
    ):
        raise RepositoryScanError("O arquivo compactado contém um caminho inseguro.")
    return posix


def _declared_zip_entry_count(archive_path: Path) -> int | None:
    with archive_path.open("rb") as source:
        source.seek(max(0, archive_path.stat().st_size - 65_557))
        tail = source.read()
    marker = tail.rfind(b"PK\x05\x06")
    if marker < 0 or len(tail) < marker + 22:
        return None
    comment_length = struct.unpack_from("<H", tail, marker + 20)[0]
    if marker + 22 + comment_length != len(tail):
        return None
    return struct.unpack_from("<H", tail, marker + 10)[0]


def _extract_zip(archive_path: Path, target: Path) -> None:
    try:
        archive_size = archive_path.stat().st_size
        if archive_size > MAX_ZIP_ARCHIVE_BYTES:
            raise RepositoryScanError(
                "O arquivo compactado excede os limites permitidos."
            )
        declared_count = _declared_zip_entry_count(archive_path)
        if declared_count is not None and (
            declared_count == 0xFFFF
            or declared_count > MAX_ZIP_FILES
            or declared_count > MAX_ZIP_ENTRIES
        ):
            raise RepositoryScanError(
                "O arquivo compactado excede os limites permitidos."
            )
        archive = zipfile.ZipFile(archive_path)
    except RepositoryScanError:
        raise
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
        raise RepositoryScanError("Não foi possível abrir o arquivo compactado.") from None

    with archive:
        entries = archive.infolist()
        file_entries = [entry for entry in entries if not entry.is_dir()]
        if (
            len(file_entries) > MAX_ZIP_FILES
            or len(entries) > MAX_ZIP_ENTRIES
        ):
            raise RepositoryScanError("O arquivo compactado excede os limites permitidos.")
        if sum(entry.file_size for entry in file_entries) > MAX_ZIP_BYTES:
            raise RepositoryScanError("O arquivo compactado excede os limites permitidos.")

        destinations: set[str] = set()
        total_copied = 0
        for entry in entries:
            relative = _zip_entry_path(entry.filename)
            mode = (entry.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode)
            if stat.S_ISLNK(mode) or file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise RepositoryScanError("O arquivo compactado contém um link ou tipo inseguro.")
            if entry.is_dir() and file_type not in (0, stat.S_IFDIR):
                raise RepositoryScanError("O arquivo compactado contém um link ou tipo inseguro.")
            if not entry.is_dir() and file_type == stat.S_IFDIR:
                raise RepositoryScanError("O arquivo compactado contém um link ou tipo inseguro.")

            key = relative.as_posix().casefold()
            if key in destinations:
                raise RepositoryScanError("O arquivo compactado contém caminhos duplicados.")
            destinations.add(key)

            destination = target.joinpath(*relative.parts)
            try:
                destination.resolve().relative_to(target.resolve())
            except ValueError:
                raise RepositoryScanError("O arquivo compactado contém um caminho inseguro.") from None
            try:
                if entry.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                raise RepositoryScanError(
                    "Não foi possível extrair o arquivo compactado."
                ) from None

            copied = 0
            try:
                with archive.open(entry) as source, destination.open("xb") as output:
                    while True:
                        chunk = source.read(64 * 1024)
                        if not chunk:
                            break
                        copied += len(chunk)
                        total_copied += len(chunk)
                        if (
                            copied > entry.file_size
                            or total_copied > MAX_ZIP_BYTES
                        ):
                            raise RepositoryScanError(
                                "O arquivo compactado excede os limites permitidos."
                            )
                        output.write(chunk)
            except (
                OSError,
                EOFError,
                NotImplementedError,
                RuntimeError,
                zlib.error,
                zipfile.BadZipFile,
            ):
                raise RepositoryScanError("Não foi possível extrair o arquivo compactado.") from None
            if copied != entry.file_size:
                raise RepositoryScanError("Não foi possível extrair o arquivo compactado.")


def scan_repository(
    caminho: str | os.PathLike[str],
    *,
    time_budget_seconds: float = 120,
) -> dict[str, Any]:
    """Analisa diretório ou ZIP e devolve achados e estado da varredura.

    Caminhos retornados são relativos à raiz analisada. Contagens representam
    ocorrências (linhas), e não regras agrupadas.
    """
    if (
        not isinstance(time_budget_seconds, (int, float))
        or not math.isfinite(time_budget_seconds)
        or time_budget_seconds < 0
    ):
        raise ValueError("O limite de tempo deve ser um número finito não negativo.")
    started = time.perf_counter()
    source_path = Path(caminho)
    if source_path.is_dir():
        return _scan_directory(
            source_path.resolve(),
            time_budget_seconds=float(time_budget_seconds),
            started=started,
        )
    if not source_path.is_file():
        raise RepositoryScanError("A entrada não é um diretório ou arquivo ZIP válido.")

    try:
        temporary = tempfile.TemporaryDirectory(prefix="vibecheck-repo-")
    except OSError:
        raise RepositoryScanError("Não foi possível preparar a análise.") from None
    try:
        root = Path(temporary.name)
        _extract_zip(source_path, root)
        return _scan_directory(
            root,
            time_budget_seconds=float(time_budget_seconds),
            started=started,
        )
    finally:
        temporary.cleanup()
