"""POM auto-resolver: resolve a customer's POM, match against Lightwell catalog,
identify CVEs in transitive dependencies, and produce a remediated POM.

Uses `mvn dependency:tree` subprocess for full transitive resolution (handles
parent POMs, BOMs, property interpolation, conflict mediation). Requires Maven
and a JDK on the host.
"""

from __future__ import annotations

import asyncio
import logging
import re
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

MAVEN_NS = "http://maven.apache.org/POM/4.0.0"
NS = {"m": MAVEN_NS}

# Pattern: "org.springframework:spring-core:jar:5.3.18:compile"
_DEP_LINE_RE = re.compile(
    r"[+\\\| -]+"  # tree drawing chars
    r"\s*"
    r"([\w.\-]+)"  # groupId
    r":"
    r"([\w.\-]+)"  # artifactId
    r":"
    r"(\w+)"  # type (jar, pom, etc.)
    r":"
    r"([\w.\-]+)"  # version
    r":"
    r"(\w+)"  # scope
)

# Root line pattern: "com.example:my-app:jar:1.0.0"
_ROOT_LINE_RE = re.compile(
    r"([\w.\-]+):([\w.\-]+):(\w+):([\w.\-]+)"
)


@dataclass
class ResolvedDep:
    group_id: str
    artifact_id: str
    version: str
    scope: str
    dep_type: str
    depth: int  # 0 = direct, >0 = transitive

    @property
    def gav(self) -> str:
        return f"{self.group_id}:{self.artifact_id}:{self.version}"

    @property
    def ga(self) -> str:
        return f"{self.group_id}:{self.artifact_id}"


@dataclass
class RemediationMatch:
    dep: ResolvedDep
    remediated_version: str
    base_version: str
    cves: list[str] = field(default_factory=list)


@dataclass
class ResolverResult:
    total_deps: int
    resolved_deps: list[ResolvedDep]
    matches: list[RemediationMatch]
    unmatched_deps: list[ResolvedDep]
    remediated_pom: str
    error: str | None = None


# ---------------------------------------------------------------------------
# Remediated package catalog
# ---------------------------------------------------------------------------

# Maps (groupId, artifactId, base_version) -> remediated_version.
# Only packages that actually exist on the public-lightwell-demo endpoint.
# In production this would be a live query against the Lightwell API.
REMEDIATION_CATALOG: dict[tuple[str, str, str], str] = {
    ("org.springframework", "spring-core", "5.3.18"): "5.3.18.rhlw-00003",
    ("com.fasterxml.woodstox", "woodstox-core", "6.0.3"): "6.0.3.rhlw-00001",
    ("org.json", "json", "20220320"): "20220320.0.0.rhlw-00003",
    ("com.jayway.jsonpath", "json-path", "2.8.0"): "2.8.0.rhlw-00001",
    ("com.jayway.jsonpath", "json-path", "2.7.0"): "2.7.0.rhlw-00001",
}

# CVE data per base version, from OSV files.
# In production this comes from osv_cve_map (already cached at app startup).
CVE_MAP: dict[str, list[str]] = {
    "5.3.18": [
        "CVE-2024-38808",
        "CVE-2023-34055",
        "CVE-2024-22262",
        "CVE-2023-20860",
        "CVE-2023-20861",
        "CVE-2023-20863",
        "CVE-2024-38816",
    ],
    "20220320": [
        "CVE-2022-45688",
        "CVE-2023-5072",
    ],
    "6.0.3": [
        "CVE-2022-40152",
    ],
    "2.8.0": [
        "CVE-2023-51074",
    ],
    "2.7.0": [
        "CVE-2023-51074",
    ],
}


# ---------------------------------------------------------------------------
# Maven dependency tree resolution
# ---------------------------------------------------------------------------

async def resolve_maven_tree(pom_content: str) -> tuple[list[ResolvedDep], str | None]:
    """Run `mvn dependency:tree` on the given POM and parse the result.

    Returns (resolved_deps, error_message).
    """
    with tempfile.TemporaryDirectory(prefix="lw-resolver-") as tmpdir:
        pom_path = Path(tmpdir) / "pom.xml"
        tree_path = Path(tmpdir) / "tree.txt"
        pom_path.write_text(pom_content, encoding="utf-8")

        cmd = [
            "mvn", "dependency:tree",
            f"-DoutputFile={tree_path}",
            "-DoutputType=text",
            f"-f", str(pom_path),
            "-B",  # batch mode, less noise
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)

        if proc.returncode != 0:
            output = stdout.decode(errors="replace")
            log.error("mvn dependency:tree failed (rc=%d): %s", proc.returncode, output[-2000:])
            return [], f"Maven resolution failed (exit {proc.returncode}). Check POM validity."

        if not tree_path.exists():
            return [], "Maven completed but produced no dependency tree output."

        tree_text = tree_path.read_text(encoding="utf-8")
        return parse_dependency_tree(tree_text), None


def parse_dependency_tree(tree_text: str) -> list[ResolvedDep]:
    """Parse `mvn dependency:tree` text output into structured deps."""
    deps: list[ResolvedDep] = []

    for line in tree_text.strip().splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Skip the root project line
        if _ROOT_LINE_RE.fullmatch(stripped):
            continue

        m = _DEP_LINE_RE.search(line)
        if not m:
            continue

        # Depth is determined by the position of the first alphanumeric char
        first_alpha = 0
        for i, ch in enumerate(line):
            if ch.isalpha():
                first_alpha = i
                break
        depth = max(0, (first_alpha - 0) // 3)

        deps.append(ResolvedDep(
            group_id=m.group(1),
            artifact_id=m.group(2),
            dep_type=m.group(3),
            version=m.group(4),
            scope=m.group(5),
            depth=depth,
        ))

    return deps


# ---------------------------------------------------------------------------
# Catalog matching
# ---------------------------------------------------------------------------

def match_against_catalog(
    deps: list[ResolvedDep],
    catalog: dict[tuple[str, str, str], str] | None = None,
    cve_map: dict[str, list[str]] | None = None,
) -> tuple[list[RemediationMatch], list[ResolvedDep]]:
    """Match resolved dependencies against the Lightwell remediation catalog.

    Returns (matches, unmatched).
    """
    if catalog is None:
        catalog = REMEDIATION_CATALOG
    if cve_map is None:
        cve_map = CVE_MAP

    matches: list[RemediationMatch] = []
    unmatched: list[ResolvedDep] = []
    seen_ga: set[str] = set()

    for dep in deps:
        if dep.scope == "test":
            continue
        if dep.ga in seen_ga:
            continue
        seen_ga.add(dep.ga)

        key = (dep.group_id, dep.artifact_id, dep.version)
        remediated = catalog.get(key)

        if remediated:
            cves = cve_map.get(dep.version, [])
            matches.append(RemediationMatch(
                dep=dep,
                remediated_version=remediated,
                base_version=dep.version,
                cves=cves,
            ))
        else:
            unmatched.append(dep)

    return matches, unmatched


# ---------------------------------------------------------------------------
# Remediated POM generation
# ---------------------------------------------------------------------------

LIGHTWELL_REPO_URL = (
    "https://packages.redhat.com/api/pulp-content/"
    "public-lightwell-demo/java/remediated/"
)


def generate_remediated_pom(
    original_pom: str,
    matches: list[RemediationMatch],
) -> str:
    """Produce a remediated POM from the original with Lightwell overrides.

    Adds:
    1. A <repositories> entry for the Lightwell Maven repo.
    2. Explicit <dependency> entries in <dependencyManagement> to pin
       remediated versions, overriding whatever the parent BOM resolves.
    """
    ET.register_namespace("", MAVEN_NS)
    tree = ET.ElementTree(ET.fromstring(original_pom))
    root = tree.getroot()

    _add_lightwell_repository(root)
    _add_dependency_management_overrides(root, matches)

    # Serialize back to string
    ET.indent(tree, space="    ")
    from io import BytesIO
    buf = BytesIO()
    tree.write(buf, xml_declaration=True, encoding="UTF-8")
    result = buf.getvalue().decode("utf-8")

    # ET drops the namespace prefix; re-add the schema attributes on the root
    # element if they were stripped. This is cosmetic for demo output.
    if 'xmlns:xsi' not in result and 'xsi:schemaLocation' not in result:
        result = result.replace(
            f'<project xmlns="{MAVEN_NS}"',
            f'<project xmlns="{MAVEN_NS}" '
            f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            f'xsi:schemaLocation="{MAVEN_NS} '
            f'https://maven.apache.org/xsd/maven-4.0.0.xsd"',
            1,
        )

    return result


def _add_lightwell_repository(root: ET.Element) -> None:
    """Add the Lightwell remediated repo to <repositories>."""
    repos = root.find(f"{{{MAVEN_NS}}}repositories")
    if repos is None:
        repos = ET.SubElement(root, f"{{{MAVEN_NS}}}repositories")

    repo = ET.SubElement(repos, f"{{{MAVEN_NS}}}repository")
    ET.SubElement(repo, f"{{{MAVEN_NS}}}id").text = "lightwell-remediated"
    ET.SubElement(repo, f"{{{MAVEN_NS}}}name").text = (
        "Red Hat Lightwell - Remediated Packages"
    )
    ET.SubElement(repo, f"{{{MAVEN_NS}}}url").text = LIGHTWELL_REPO_URL


def _add_dependency_management_overrides(
    root: ET.Element,
    matches: list[RemediationMatch],
) -> None:
    """Add <dependencyManagement> overrides to pin remediated versions."""
    if not matches:
        return

    dep_mgmt = root.find(f"{{{MAVEN_NS}}}dependencyManagement")
    if dep_mgmt is None:
        dep_mgmt = ET.SubElement(root, f"{{{MAVEN_NS}}}dependencyManagement")

    deps_elem = dep_mgmt.find(f"{{{MAVEN_NS}}}dependencies")
    if deps_elem is None:
        deps_elem = ET.SubElement(dep_mgmt, f"{{{MAVEN_NS}}}dependencies")

    for match in matches:
        dep = ET.SubElement(deps_elem, f"{{{MAVEN_NS}}}dependency")
        ET.SubElement(dep, f"{{{MAVEN_NS}}}groupId").text = match.dep.group_id
        ET.SubElement(dep, f"{{{MAVEN_NS}}}artifactId").text = match.dep.artifact_id
        ET.SubElement(dep, f"{{{MAVEN_NS}}}version").text = match.remediated_version


# ---------------------------------------------------------------------------
# Top-level resolver
# ---------------------------------------------------------------------------

async def resolve_pom(pom_content: str) -> ResolverResult:
    """Full pipeline: resolve -> match -> generate remediated POM."""
    resolved, error = await resolve_maven_tree(pom_content)

    if error:
        return ResolverResult(
            total_deps=0,
            resolved_deps=[],
            matches=[],
            unmatched_deps=[],
            remediated_pom="",
            error=error,
        )

    matches, unmatched = match_against_catalog(resolved)

    remediated_pom = ""
    if matches:
        remediated_pom = generate_remediated_pom(pom_content, matches)

    return ResolverResult(
        total_deps=len(resolved),
        resolved_deps=resolved,
        matches=matches,
        unmatched_deps=unmatched,
        remediated_pom=remediated_pom,
    )
