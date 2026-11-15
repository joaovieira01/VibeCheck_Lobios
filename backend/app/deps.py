"""Verificação opcional de dependências em registries públicos e no OSV."""

from __future__ import annotations

import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from http.client import HTTPException
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from app.scanner import Finding

OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
REQUEST_TIMEOUT_SECONDS = 3
MAX_PACKAGES_PER_FILE = 50
MAX_CONCURRENT_REQUESTS = 5
_REQUEST_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)

_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?\s*(.*?)\s*$"
)
_PYTHON_PIN = re.compile(r"^(?:===|==)\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)$")
_NPM_PIN = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_PYPI_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
_NPM_NAME = re.compile(
    r"^(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9][A-Za-z0-9._~-]*$"
)
_LOCAL_DEPENDENCY = re.compile(r"^(?:file:|link:|workspace:|git\+|github:)", re.I)


class HTTPJSONClient(Protocol):
    def get_json(self, url: str, timeout: float) -> Any: ...

    def post_json(self, url: str, payload: dict[str, Any], timeout: float) -> Any: ...


class UrllibHTTPClient:
    """Cliente HTTPS pequeno para permitir testes com um transporte substituto."""

    @staticmethod
    def _read_json(request: Request, timeout: float) -> Any:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def get_json(self, url: str, timeout: float) -> Any:
        request = Request(url, headers={"User-Agent": "VibeCheck-SCA/1.0"})
        return self._read_json(request, timeout)

    def post_json(self, url: str, payload: dict[str, Any], timeout: float) -> Any:
        request = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "VibeCheck-SCA/1.0",
            },
            method="POST",
        )
        return self._read_json(request, timeout)


@dataclass(frozen=True)
class Dependency:
    name: str
    ecosystem: str
    version: str | None
    line: int
    evidence: str


@dataclass
class DependencyCheckResult:
    findings: list[Finding]
    status: str
    packages_checked: int

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": self.status,
            "packagesChecked": self.packages_checked,
        }
        if self.status == "indisponivel":
            result["message"] = "Verificação online indisponível."
        elif self.status == "limitada":
            result["message"] = (
                f"Limite de {MAX_PACKAGES_PER_FILE} pacotes por arquivo; "
                "alguns pacotes não foram verificados."
            )
        return result


def online_dependencies_enabled() -> bool:
    return os.environ.get("VIBECHECK_ONLINE_DEPS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _extract_dependencies(source: str, filename: str) -> list[Dependency]:
    basename = filename.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    dependencies: list[Dependency] = []
    if basename == "requirements.txt":
        for line_number, raw_line in enumerate(source.splitlines(), start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            match = _REQUIREMENT.match(line)
            if match is None:
                continue
            name, specifier = match.groups()
            version_specifier = specifier.split(";", 1)[0].strip()
            pin = _PYTHON_PIN.fullmatch(version_specifier)
            dependencies.append(
                Dependency(
                    name=name,
                    ecosystem="PyPI",
                    version=pin.group(1) if pin else None,
                    line=line_number,
                    evidence=raw_line.strip()[:500],
                )
            )
        return dependencies

    if basename != "package.json":
        return dependencies
    try:
        manifest = json.loads(source)
    except ValueError:
        return dependencies
    if not isinstance(manifest, dict):
        return dependencies

    for group in ("dependencies", "devDependencies", "optionalDependencies"):
        entries = manifest.get(group)
        if not isinstance(entries, dict):
            continue
        for name, raw_version in entries.items():
            if not isinstance(name, str) or not isinstance(raw_version, str):
                continue
            if _LOCAL_DEPENDENCY.match(raw_version.strip()):
                continue
            match = re.search(
                rf'"{re.escape(name)}"\s*:\s*"{re.escape(raw_version)}"',
                source,
            )
            line = source.count("\n", 0, match.start()) + 1 if match else 1
            version = raw_version if _NPM_PIN.fullmatch(raw_version) else None
            dependencies.append(
                Dependency(
                    name=name,
                    ecosystem="npm",
                    version=version,
                    line=line,
                    evidence=f'"{name}": "{raw_version}"'[:500],
                )
            )
    return dependencies


def _valid_package_name(dependency: Dependency) -> bool:
    if dependency.ecosystem == "PyPI":
        return _PYPI_NAME.fullmatch(dependency.name) is not None
    return _NPM_NAME.fullmatch(dependency.name) is not None


def _registry_url(dependency: Dependency) -> str:
    if dependency.ecosystem == "PyPI":
        return f"https://pypi.org/pypi/{quote(dependency.name, safe='')}/json"
    return f"https://registry.npmjs.org/{quote(dependency.name, safe='@')}"


def _package_exists(client: HTTPJSONClient, dependency: Dependency) -> bool:
    try:
        client.get_json(_registry_url(dependency), REQUEST_TIMEOUT_SECONDS)
    except HTTPError as exc:
        if exc.code == 404:
            return False
        raise
    return True


def _bounded_package_exists(
    client: HTTPJSONClient, dependency: Dependency
) -> bool:
    with _REQUEST_SLOTS:
        return _package_exists(client, dependency)


def _advisory_id(vulnerability: dict[str, Any]) -> str:
    aliases = vulnerability.get("aliases", [])
    if not isinstance(aliases, list):
        aliases = []
    identifiers = [
        alias
        for alias in aliases
        if isinstance(alias, str)
        and (alias.startswith("CVE-") or alias.startswith("GHSA-"))
    ]
    if identifiers:
        return sorted(identifiers, key=lambda item: (not item.startswith("CVE-"), item))[0]
    identifier = vulnerability.get("id")
    return identifier if isinstance(identifier, str) and identifier else "OSV"


def _fixed_versions(vulnerability: dict[str, Any]) -> list[str]:
    fixed: list[str] = []
    affected_items = vulnerability.get("affected", [])
    if not isinstance(affected_items, list):
        return fixed
    for affected in affected_items:
        if not isinstance(affected, dict):
            continue
        ranges = affected.get("ranges", [])
        if not isinstance(ranges, list):
            continue
        for version_range in ranges:
            if not isinstance(version_range, dict):
                continue
            events = version_range.get("events", [])
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, dict):
                    version = event.get("fixed")
                    if isinstance(version, str) and version not in fixed:
                        fixed.append(version)
    return fixed


def _vulnerability_finding(
    dependency: Dependency, vulnerability: dict[str, Any]
) -> Finding:
    advisory = _advisory_id(vulnerability)
    fixed = _fixed_versions(vulnerability)
    remediation = (
        f" Versão corrigida disponível: {', '.join(fixed)}."
        if fixed
        else " Consulte o aviso para escolher uma versão corrigida."
    )
    return Finding(
        id="vulnerable-dependency",
        title=f"Dependência vulnerável: {advisory}",
        severity="Alta",
        cwe="CWE-1395",
        owasp_id="A06",
        owasp_name="Componentes vulneráveis e desatualizados",
        description=(
            f"O pacote {dependency.name} versão {dependency.version} tem a "
            f"vulnerabilidade conhecida {advisory}.{remediation}"
        ),
        recommendation=(
            f"Atualize {dependency.name} para uma versão corrigida."
            if fixed
            else f"Verifique o aviso {advisory} e escolha uma versão corrigida."
        ),
        impact="Uma falha conhecida na dependência pode comprometer o aplicativo.",
        prevention="Atualize as dependências e acompanhe avisos de segurança.",
        locations=[dependency.line],
        evidence=[dependency.evidence],
    )


def _nonexistent_finding(dependency: Dependency) -> Finding:
    return Finding(
        id="nonexistent-dependency",
        title="Pacote inexistente",
        severity="Alta",
        cwe="CWE-1357",
        owasp_id="A06",
        owasp_name="Componentes vulneráveis e desatualizados",
        description=(
            "pacote inexistente, possível alucinação de IA ou typosquatting"
        ),
        recommendation="Confirme o nome e a origem do pacote antes de instalá-lo.",
        impact="Um pacote inventado ou parecido com outro pode introduzir código malicioso.",
        prevention="Confira o pacote no registry oficial antes de adicioná-lo.",
        locations=[dependency.line],
        evidence=[dependency.evidence],
    )


def _query_osv(
    client: HTTPJSONClient, dependencies: list[Dependency]
) -> list[list[dict[str, Any]]]:
    payload = {
        "queries": [
            {
                "package": {
                    "name": dependency.name,
                    "ecosystem": dependency.ecosystem,
                },
                "version": dependency.version,
            }
            for dependency in dependencies
        ]
    }
    response = client.post_json(
        OSV_QUERY_BATCH_URL, payload, REQUEST_TIMEOUT_SECONDS
    )
    results = response.get("results") if isinstance(response, dict) else None
    if not isinstance(results, list) or len(results) != len(dependencies):
        raise ValueError("Resposta do OSV inválida.")
    vulnerabilities: list[list[dict[str, Any]]] = []
    for result in results:
        items = result.get("vulns", []) if isinstance(result, dict) else None
        if not isinstance(items, list) or any(
            not isinstance(item, dict) for item in items
        ):
            raise ValueError("Resposta do OSV inválida.")
        vulnerabilities.append(items)
    return vulnerabilities


def _bounded_query_osv(
    client: HTTPJSONClient, dependencies: list[Dependency]
) -> list[list[dict[str, Any]]]:
    with _REQUEST_SLOTS:
        return _query_osv(client, dependencies)


def check_dependencies(
    source: str,
    filename: str,
    *,
    client: HTTPJSONClient | None = None,
) -> DependencyCheckResult:
    """Consulta registries sem deixar falhas externas interromperem a análise."""
    dependencies = _extract_dependencies(source, filename)
    if not dependencies:
        return DependencyCheckResult([], "concluida", 0)

    limited = len(dependencies) > MAX_PACKAGES_PER_FILE
    dependencies = dependencies[:MAX_PACKAGES_PER_FILE]
    client = client or UrllibHTTPClient()
    findings: list[Finding] = []
    unavailable = False
    valid_dependencies = [
        dependency for dependency in dependencies if _valid_package_name(dependency)
    ]
    if len(valid_dependencies) != len(dependencies):
        unavailable = True

    pinned = [item for item in valid_dependencies if item.version is not None]
    vulnerabilities: list[list[dict[str, Any]]] = [[] for _ in pinned]

    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_REQUESTS) as executor:
        existence_futures = {
            executor.submit(_bounded_package_exists, client, dependency): dependency
            for dependency in valid_dependencies
        }
        osv_future = (
            executor.submit(_bounded_query_osv, client, pinned) if pinned else None
        )
        existence_results: dict[Dependency, bool | None] = {}
        for future in as_completed(existence_futures):
            dependency = existence_futures[future]
            try:
                existence_results[dependency] = future.result()
            except (
                HTTPError,
                URLError,
                TimeoutError,
                OSError,
                HTTPException,
                ValueError,
            ):
                unavailable = True
                existence_results[dependency] = None
        for dependency in valid_dependencies:
            if existence_results.get(dependency) is False:
                findings.append(_nonexistent_finding(dependency))

        if osv_future is not None:
            try:
                vulnerabilities = osv_future.result()
            except (
                HTTPError,
                URLError,
                TimeoutError,
                OSError,
                HTTPException,
                ValueError,
            ):
                unavailable = True

    for dependency, advisories in zip(pinned, vulnerabilities):
        findings.extend(
            _vulnerability_finding(dependency, advisory)
            for advisory in advisories
        )

    status = (
        "indisponivel"
        if unavailable
        else "limitada"
        if limited
        else "concluida"
    )
    return DependencyCheckResult(findings, status, len(valid_dependencies))
