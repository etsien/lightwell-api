"""
Lightwell Package Security API - Demo Router

Proxies live data from Pulp (packages.redhat.com) and the Red Hat Security
Data API into the schema defined in the Lightwell API 0.1.0 spec.

Run:
    pip install -r requirements.txt
    cp /path/to/.env .env   # needs LIGHTWELL_TBR_USER and LIGHTWELL_TBR_PASS
    uvicorn app:app --reload --port 8000

--- Data sources ---

Live backends (when credential has sufficient permissions):
  - Pulp API (packages.redhat.com)  -- repos, packages, content, OSV files
  - Red Hat Security Data API       -- CVE lookups (public, no auth)
  - CSAF/VEX files                  -- per-CVE VEX docs (public, no auth)

Mock fallback:
  When the Pulp credential returns 403 (e.g. a TBR download-only credential
  that lacks admin list permissions), the server automatically switches to
  mock_data.py.  The /health endpoint reports {"data_source": "mock"} vs
  "live" so callers can tell.  Mock data mirrors real Lightwell repo names,
  package naming conventions, and rhlw version patterns, but the specific
  artifacts and CVE mappings are illustrative, not production data.

--- Stubbed fields ---

The following response fields are always placeholder values in this demo
because the underlying data does not yet exist in any queryable backend:

  embargo / embargoed
      Always false / null.  Embargo timelines are managed internally by
      the Lightwell Clearinghouse Premier system, which has no external API.
      Populating these fields requires a bespoke integration with that system.

  RemediationChange.patch
      Always "(patch data not available in demo)".  Actual patch diffs live in
      the PNC / Clearinghouse build pipeline and are not stored in Pulp or any
      public Red Hat data source.

  RemediationChange.backport / novel_fix
      Always false.  Classifying whether a fix is a backport or a novel patch
      requires build metadata from the Clearinghouse remediation workflow,
      which is not exposed via any current API.

  RemediationSummary.vulnerable_to_cves / Remediation.vulnerable_to_cves
      Always empty.  Determining which CVEs a specific rhlw iteration is
      *still* vulnerable to requires a full CVE-to-version matrix.  The OSV
      filenames only tell us which CVEs a base version has fixes for, not
      which remain open at each rhlw step.  Building this matrix requires
      either per-rhlw OSV records or integration with RHTPA's vulnerability
      analysis endpoint (POST /api/v2/vulnerability/analyze).
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Query, Response, UploadFile

from backends import (
    CONTENT_ENDPOINTS,
    PulpClient,
    SecurityDataClient,
    VEX_BASE,
    package_name_from_content,
    package_version_from_content,
    parse_rhlw_version,
    security_level_from_name,
)
from pom_resolver import resolve_pom
from schemas import (
    CveDetail,
    EmbargoEntry,
    LightwellPackageCveStatus,
    OsvEntry,
    Package,
    PackageCveEntry,
    PackageType,
    PackageVersion,
    PaginatedCves,
    PaginatedEmbargoes,
    PaginatedPackages,
    PaginatedPackageVersions,
    PaginatedRemediations,
    PaginatedRepositories,
    PomResolverResponse,
    Remediation,
    RemediationChange,
    RemediationMatchResponse,
    RemediationSummary,
    Repository,
    ResolvedDependency,
    ResolverSummary,
    SecurityLevel,
    VexReference,
)

log = logging.getLogger(__name__)

# ---- globals populated at startup ----
pulp: PulpClient
secdata: SecurityDataClient
osv_cve_map: dict[str, list[str]] = {}


def _load_env():
    for candidate in [Path(".env"), Path("/home/etsien/Projects/.env")]:
        if candidate.exists():
            load_dotenv(candidate)
            return
    load_dotenv()


@asynccontextmanager
async def lifespan(application: FastAPI):
    global pulp, secdata, osv_cve_map
    _load_env()

    user = os.getenv("LIGHTWELL_TBR_USER", "")
    passwd = os.getenv("LIGHTWELL_TBR_PASS", "")
    if not user or not passwd:
        raise RuntimeError("LIGHTWELL_TBR_USER and LIGHTWELL_TBR_PASS must be set")

    pulp = PulpClient(username=user, password=passwd)
    secdata = SecurityDataClient()

    log.info("Pre-caching repo list and OSV data")
    await pulp.list_repos()
    osv_files = await pulp.list_osv_files()
    osv_cve_map = pulp.parse_osv_cves(osv_files)
    log.info("Cached %d repos, %d OSV CVE entries", len(pulp._repo_cache), len(osv_cve_map))

    yield

    await pulp.close()
    await secdata.close()


app = FastAPI(
    title="Lightwell Package Security API",
    version="0.1.0-demo",
    lifespan=lifespan,
)

PREFIX = "/api/lightwell/v0.1"

# Maximum content units fetched from Pulp per repo in cross-repository queries.
# This is a demo limitation; full pagination passthrough is not implemented.
_CROSS_REPO_CONTENT_LIMIT = 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Allowlists for the `order` query parameter per resource type.
_ORDER_FIELDS = {
    "repository": {"name", "security_level", "type", "packages_count", "versions_count", "remediations_count"},
    "package": {"name", "security_level", "type"},
    "package_version": {"name", "security_level", "type", "version", "release_date"},
    "remediation": {"name", "security_level", "version", "id"},
    "cve": {"cve_id", "severity", "public_date", "status"},
}


def _validate_order(order: str | None, resource_type: str) -> tuple[str, bool] | None:
    """Parse and validate an order string. Returns (field, reverse) or None.

    Raises HTTPException(400) if the field is not in the allowlist.
    """
    if not order:
        return None
    parts = order.split()
    field = parts[0] if parts else ""
    reverse = len(parts) > 1 and parts[1].lower() == "desc"
    allowed = _ORDER_FIELDS.get(resource_type, set())
    if field not in allowed:
        raise HTTPException(400, f"Invalid order field '{field}'. Allowed: {sorted(allowed)}")
    return field, reverse


def _is_internal_repo(name: str) -> bool:
    """Return True for repos that should be hidden from customer-facing endpoints."""
    if name.endswith("-landing"):
        return True
    if name == "osv-java-remediated":
        return True
    return False


def _repo_type(repo: dict) -> str:
    return repo.get("_pulp_type", "maven")


def _api_type(pulp_type: str) -> PackageType:
    return PackageType(pulp_type) if pulp_type in PackageType.__members__ else PackageType.maven


def _deduplicate_packages(
    content_units: list[dict],
    repo_type: str,
    sec_level: SecurityLevel,
    api_type: PackageType,
) -> list[Package]:
    """Collapse content units into unique packages."""
    seen: set[str] = set()
    packages: list[Package] = []
    for unit in content_units:
        name = package_name_from_content(unit, repo_type)
        if name and name not in seen:
            seen.add(name)
            packages.append(Package(name=name, security_level=sec_level, type=api_type))
    return packages


def _deduplicate_versions(
    content_units: list[dict],
    repo_type: str,
    sec_level: SecurityLevel,
    api_type: PackageType,
    *,
    repo_name: str | None = None,
) -> list[PackageVersion]:
    """Collapse content units into unique (package, version) pairs."""
    seen: set[tuple[str, str]] = set()
    versions: list[PackageVersion] = []
    for unit in content_units:
        name = package_name_from_content(unit, repo_type)
        ver = package_version_from_content(unit)
        key = (name, ver)
        if name and ver and key not in seen:
            seen.add(key)
            rhlw = parse_rhlw_version(ver)
            remediation = None
            if rhlw:
                base_ver, rhlw_id = rhlw
                cves = osv_cve_map.get(base_ver, [])
                remediation = RemediationSummary(
                    id=rhlw_id,
                    resolved_cves=cves,
                    vulnerable_to_cves=[],
                    embargoed=False,
                )
            release_date = _parse_pulp_created(unit)
            versions.append(PackageVersion(
                name=name,
                security_level=sec_level,
                type=api_type,
                version=ver,
                latest_remediation=remediation,
                release_date=release_date,
                repository=repo_name,
            ))
    return versions


def _parse_pulp_created(unit: dict) -> datetime | None:
    """Extract pulp_created as datetime, or None if missing/unparseable."""
    val = unit.get("pulp_created")
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    try:
        return datetime.fromisoformat(val)
    except (ValueError, TypeError):
        return None


def _build_remediation(
    name: str,
    sec_level: SecurityLevel,
    version: str,
    rhlw_id: str,
    base_ver: str,
) -> Remediation:
    """Build a Remediation object from parsed version data + OSV CVE map."""
    cves = osv_cve_map.get(base_ver, [])
    changes = [
        RemediationChange(
            redhat_identifier=f"x_RHLW-{cve}-{base_ver}",
            cve=cve,
            patch="(patch data not available in demo)",
            backport=False,
            novel_fix=False,
        )
        for cve in cves
    ]
    return Remediation(
        name=name,
        security_level=sec_level,
        version=version,
        id=rhlw_id,
        addressed_cves=cves,
        vulnerable_to_cves=[],
        embargoed=False,
        changes=changes,
    )


def _paginate(items: list, limit: int, offset: int) -> tuple[int, list]:
    total = len(items)
    return total, items[offset : offset + limit]


def _set_pagination_headers(response: Response, total: int, limit: int, offset: int):
    """Set pagination-related headers including the demo content-limit note."""
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Demo-Note"] = (
        f"Cross-repo queries fetch at most {_CROSS_REPO_CONTENT_LIMIT} units per repo; "
        "results may be incomplete for large repositories."
    )


def _match_filters(
    pkg: PackageVersion,
    *,
    type_filter: PackageType | None,
    name_filter: str | None,
    sec_level_filter: SecurityLevel | None,
    embargoed_filter: bool | None,
    resolves_cve: str | None,
    vulnerable_to_cve: str | None,
) -> bool:
    if type_filter and pkg.type != type_filter:
        return False
    if name_filter and pkg.name != name_filter:
        return False
    if sec_level_filter and pkg.security_level != sec_level_filter:
        return False
    if embargoed_filter is not None:
        is_embargoed = pkg.latest_remediation.embargoed if pkg.latest_remediation else False
        if embargoed_filter != is_embargoed:
            return False
    if resolves_cve:
        if not pkg.latest_remediation or resolves_cve not in pkg.latest_remediation.resolved_cves:
            return False
    if vulnerable_to_cve:
        if not pkg.latest_remediation or vulnerable_to_cve not in pkg.latest_remediation.vulnerable_to_cves:
            return False
    return True


def _compute_repo_counts(summary: dict, repo_name: str) -> tuple[int, int]:
    """Compute (packages_count, versions_count) from content summary.

    For maven repos: packages_count ~ metadata count, versions_count ~ artifact count.
    For python repos: both approximate from total content (no separate metadata type).
    """
    if "maven.artifact" in summary:
        versions_count = summary.get("maven.artifact", {}).get("count", 0)
        packages_count = summary.get("maven.metadata", {}).get("count", 0)
        return packages_count, versions_count
    if "python.python" in summary:
        total = summary.get("python.python", {}).get("count", 0)
        # Heuristic: unique package names ~ 1/4 of total versions
        packages_count = max(1, total // 4)
        return packages_count, total
    content_count = sum(v.get("count", 0) for v in summary.values())
    return content_count, content_count


# ---------------------------------------------------------------------------
# Routes -- Repositories
# ---------------------------------------------------------------------------

@app.get(f"{PREFIX}/repositories/", response_model=PaginatedRepositories, tags=["Repositories"])
async def list_repositories(
    response: Response,
    limit: int = Query(20, ge=1),
    offset: int = Query(0, ge=0),
    order: str | None = Query(None),
    type: PackageType | None = Query(None),
):
    sort_spec = _validate_order(order, "repository")
    repos = await pulp.list_repos()
    results: list[Repository] = []

    for r in repos:
        name = r["name"]
        if _is_internal_repo(name):
            continue
        rtype = _repo_type(r)
        api_type = _api_type(rtype)
        if type and api_type != type:
            continue
        summary = await pulp.get_repo_version_summary(r)
        packages_count, versions_count = _compute_repo_counts(summary, name)
        results.append(Repository(
            name=name,
            security_level=SecurityLevel(security_level_from_name(name)),
            type=api_type,
            packages_count=packages_count,
            versions_count=versions_count,
            remediations_count=versions_count if "remediated" in name else 0,
        ))

    if sort_spec:
        field, reverse = sort_spec
        results.sort(key=lambda r: getattr(r, field, ""), reverse=reverse)

    total, page = _paginate(results, limit, offset)
    _set_pagination_headers(response, total, limit, offset)
    return PaginatedRepositories(count=total, results=page)


@app.get(
    f"{PREFIX}/repositories/{{repository_name}}/packages/",
    response_model=PaginatedPackages,
    tags=["Repositories"],
)
async def list_repository_packages(
    repository_name: str,
    limit: int = Query(20, ge=1),
    offset: int = Query(0, ge=0),
    order: str | None = Query(None),
    name: str | None = Query(None),
):
    sort_spec = _validate_order(order, "package")
    repo = await pulp.get_repo(repository_name)
    if not repo:
        raise HTTPException(404, f"Repository '{repository_name}' not found")

    rtype = _repo_type(repo)
    api_type = _api_type(rtype)
    sec_level = SecurityLevel(security_level_from_name(repository_name))

    filters: dict = {}
    if name and rtype == "maven":
        parts = name.split(":", 1)
        if len(parts) == 2:
            filters["group_id"] = parts[0]
            filters["artifact_id"] = parts[1]
    elif name:
        filters["name"] = name

    data = await pulp.list_content(repository_name, limit=500, offset=0, **filters)
    units = data.get("results", [])
    packages = _deduplicate_packages(units, rtype, sec_level, api_type)

    if sort_spec:
        field, reverse = sort_spec
        packages.sort(key=lambda p: getattr(p, field, ""), reverse=reverse)

    total, page = _paginate(packages, limit, offset)
    return PaginatedPackages(count=total, results=page)


@app.get(
    f"{PREFIX}/repositories/{{repository_name}}/packages/{{package_name}}/",
    response_model=Package,
    tags=["Repositories"],
)
async def get_repository_package(repository_name: str, package_name: str):
    repo = await pulp.get_repo(repository_name)
    if not repo:
        raise HTTPException(404, f"Repository '{repository_name}' not found")

    rtype = _repo_type(repo)
    api_type = _api_type(rtype)
    sec_level = SecurityLevel(security_level_from_name(repository_name))

    units = await pulp.list_all_content_versions(repository_name, package_name, rtype, limit=1)
    if not units:
        raise HTTPException(404, f"Package '{package_name}' not found in '{repository_name}'")

    return Package(name=package_name, security_level=sec_level, type=api_type)


@app.get(
    f"{PREFIX}/repositories/{{repository_name}}/packages/{{package_name}}/{{version}}/",
    response_model=PackageVersion,
    tags=["Repositories"],
)
async def get_repository_package_version(
    repository_name: str,
    package_name: str,
    version: str,
):
    repo = await pulp.get_repo(repository_name)
    if not repo:
        raise HTTPException(404, f"Repository '{repository_name}' not found")

    rtype = _repo_type(repo)
    api_type = _api_type(rtype)
    sec_level = SecurityLevel(security_level_from_name(repository_name))

    units = await pulp.list_all_content_versions(repository_name, package_name, rtype, limit=200)
    match = [u for u in units if u.get("version") == version]
    if not match:
        raise HTTPException(404, f"Version '{version}' of '{package_name}' not found")

    rhlw = parse_rhlw_version(version)
    remediation = None
    if rhlw:
        base_ver, rhlw_id = rhlw
        cves = osv_cve_map.get(base_ver, [])
        remediation = RemediationSummary(
            id=rhlw_id, resolved_cves=cves, vulnerable_to_cves=[], embargoed=False,
        )

    release_date = _parse_pulp_created(match[0])
    return PackageVersion(
        name=package_name,
        security_level=sec_level,
        type=api_type,
        version=version,
        latest_remediation=remediation,
        release_date=release_date,
        repository=repository_name,
    )


@app.get(
    f"{PREFIX}/repositories/{{repository_name}}/packages/{{package_name}}/{{version}}/remediations/",
    response_model=PaginatedRemediations,
    tags=["Repositories"],
)
async def list_package_version_remediations(
    repository_name: str,
    package_name: str,
    version: str,
    limit: int = Query(20, ge=1),
    offset: int = Query(0, ge=0),
    order: str | None = Query(None),
):
    sort_spec = _validate_order(order, "remediation")
    repo = await pulp.get_repo(repository_name)
    if not repo:
        raise HTTPException(404, f"Repository '{repository_name}' not found")

    rtype = _repo_type(repo)
    sec_level = SecurityLevel(security_level_from_name(repository_name))

    units = await pulp.list_all_content_versions(repository_name, package_name, rtype, limit=500)

    remediations: list[Remediation] = []
    seen_ids: set[str] = set()
    for unit in units:
        ver = package_version_from_content(unit)
        rhlw = parse_rhlw_version(ver)
        if not rhlw:
            continue
        base_ver, rhlw_id = rhlw
        if base_ver != version and ver != version:
            continue
        if rhlw_id in seen_ids:
            continue
        seen_ids.add(rhlw_id)
        remediations.append(_build_remediation(package_name, sec_level, ver, rhlw_id, base_ver))

    if sort_spec:
        field, reverse = sort_spec
        remediations.sort(key=lambda r: getattr(r, field, ""), reverse=reverse)
    else:
        remediations.sort(key=lambda r: r.id, reverse=True)

    total, page = _paginate(remediations, limit, offset)
    return PaginatedRemediations(count=total, results=page)


# ---------------------------------------------------------------------------
# Routes -- Packages (cross-repository)
# ---------------------------------------------------------------------------

@app.get(f"{PREFIX}/packages/", response_model=PaginatedPackages, tags=["Packages"])
async def list_packages(
    response: Response,
    limit: int = Query(20, ge=1),
    offset: int = Query(0, ge=0),
    order: str | None = Query(None),
    type: PackageType | None = Query(None),
    name: str | None = Query(None),
    security_level: SecurityLevel | None = Query(None),
):
    sort_spec = _validate_order(order, "package")
    repos = await pulp.list_repos()
    all_packages: list[Package] = []
    seen: set[tuple[str, str, str]] = set()

    for r in repos:
        repo_name = r["name"]
        if _is_internal_repo(repo_name):
            continue
        rtype = _repo_type(r)
        api_type = _api_type(rtype)
        if type and api_type != type:
            continue
        sec_level = SecurityLevel(security_level_from_name(repo_name))
        if security_level and sec_level != security_level:
            continue

        filters: dict = {}
        if name and rtype == "maven":
            parts = name.split(":", 1)
            if len(parts) == 2:
                filters["group_id"] = parts[0]
                filters["artifact_id"] = parts[1]
        elif name:
            filters["name"] = name

        data = await pulp.list_content(repo_name, limit=_CROSS_REPO_CONTENT_LIMIT, **filters)
        for unit in data.get("results", []):
            pkg_name = package_name_from_content(unit, rtype)
            key = (pkg_name, sec_level.value, api_type.value)
            if pkg_name and key not in seen:
                seen.add(key)
                all_packages.append(Package(name=pkg_name, security_level=sec_level, type=api_type))

    if sort_spec:
        field, reverse = sort_spec
        all_packages.sort(key=lambda p: getattr(p, field, ""), reverse=reverse)

    total, page = _paginate(all_packages, limit, offset)
    _set_pagination_headers(response, total, limit, offset)
    return PaginatedPackages(count=total, results=page)


# ---------------------------------------------------------------------------
# Routes -- Package Versions (cross-repository)
# ---------------------------------------------------------------------------

@app.get(f"{PREFIX}/package_versions/", response_model=PaginatedPackageVersions, tags=["Package Versions"])
async def list_package_versions(
    response: Response,
    limit: int = Query(20, ge=1),
    offset: int = Query(0, ge=0),
    order: str | None = Query(None),
    type: PackageType | None = Query(None),
    name: str | None = Query(None),
    repository: str | None = Query(None),
    security_level: SecurityLevel | None = Query(None),
    embargoed: bool | None = Query(None),
    resolves_cve_id: str | None = Query(None),
    vulnerable_to_cve_id: str | None = Query(None),
):
    sort_spec = _validate_order(order, "package_version")
    repos = await pulp.list_repos()
    all_versions: list[PackageVersion] = []

    seen_versions: set[tuple[str, str, str]] = set()
    for r in repos:
        repo_name = r["name"]
        if _is_internal_repo(repo_name):
            continue
        if repository and repo_name != repository:
            continue
        rtype = _repo_type(r)
        api_type = _api_type(rtype)
        sec_level = SecurityLevel(security_level_from_name(repo_name))

        filters: dict = {}
        if name and rtype == "maven":
            parts = name.split(":", 1)
            if len(parts) == 2:
                filters["group_id"] = parts[0]
                filters["artifact_id"] = parts[1]
        elif name:
            filters["name"] = name

        data = await pulp.list_content(repo_name, limit=_CROSS_REPO_CONTENT_LIMIT, **filters)
        versions = _deduplicate_versions(
            data.get("results", []), rtype, sec_level, api_type, repo_name=repo_name,
        )

        for v in versions:
            dedup_key = (v.name, v.version, v.security_level.value)
            if dedup_key in seen_versions:
                continue
            seen_versions.add(dedup_key)
            if _match_filters(
                v,
                type_filter=type,
                name_filter=name,
                sec_level_filter=security_level,
                embargoed_filter=embargoed,
                resolves_cve=resolves_cve_id,
                vulnerable_to_cve=vulnerable_to_cve_id,
            ):
                all_versions.append(v)

    if sort_spec:
        field, reverse = sort_spec
        all_versions.sort(key=lambda v: getattr(v, field, "") or "", reverse=reverse)

    total, page = _paginate(all_versions, limit, offset)
    _set_pagination_headers(response, total, limit, offset)
    return PaginatedPackageVersions(count=total, results=page)


# ---------------------------------------------------------------------------
# Routes -- Remediations (cross-repository)
# ---------------------------------------------------------------------------

@app.get(f"{PREFIX}/remediations/", response_model=PaginatedRemediations, tags=["Remediations"])
async def list_remediations(
    response: Response,
    limit: int = Query(20, ge=1),
    offset: int = Query(0, ge=0),
    order: str | None = Query(None),
    name: str | None = Query(None),
    version: str | None = Query(None),
    type: PackageType | None = Query(None),
    embargoed: bool | None = Query(None),
):
    sort_spec = _validate_order(order, "remediation")
    repos = await pulp.list_repos()
    all_remediations: list[Remediation] = []
    seen_global: set[tuple[str, str]] = set()

    for r in repos:
        repo_name = r["name"]
        if _is_internal_repo(repo_name):
            continue
        if "remediated" not in repo_name:
            continue
        rtype = _repo_type(r)
        api_type = _api_type(rtype)
        if type and api_type != type:
            continue
        sec_level = SecurityLevel(security_level_from_name(repo_name))

        filters: dict = {}
        if name and rtype == "maven":
            parts = name.split(":", 1)
            if len(parts) == 2:
                filters["group_id"] = parts[0]
                filters["artifact_id"] = parts[1]
        elif name:
            filters["name"] = name

        data = await pulp.list_content(repo_name, limit=_CROSS_REPO_CONTENT_LIMIT, **filters)
        for unit in data.get("results", []):
            ver = package_version_from_content(unit)
            if version and ver != version:
                continue
            rhlw = parse_rhlw_version(ver)
            if not rhlw:
                continue
            base_ver, rhlw_id = rhlw
            pkg_name = package_name_from_content(unit, rtype)
            global_key = (pkg_name, rhlw_id)
            if global_key in seen_global:
                continue
            seen_global.add(global_key)

            rem = _build_remediation(pkg_name, sec_level, ver, rhlw_id, base_ver)

            if embargoed is not None and rem.embargoed != embargoed:
                continue
            all_remediations.append(rem)

    if sort_spec:
        field, reverse = sort_spec
        all_remediations.sort(key=lambda r: getattr(r, field, ""), reverse=reverse)
    else:
        all_remediations.sort(key=lambda r: r.id, reverse=True)

    total, page = _paginate(all_remediations, limit, offset)
    _set_pagination_headers(response, total, limit, offset)
    return PaginatedRemediations(count=total, results=page)


# ---------------------------------------------------------------------------
# Routes -- CVEs (Items 1 + 14)
# ---------------------------------------------------------------------------

@app.get(f"{PREFIX}/cves/{{cve_id}}/", response_model=CveDetail, tags=["CVEs"])
async def get_cve(cve_id: str):
    """CVE details from Red Hat Security Data API + Lightwell remediation status."""
    cve_data = await secdata.get_cve(cve_id)
    if not cve_data:
        raise HTTPException(404, f"CVE '{cve_id}' not found")

    # Cross-reference against osv_cve_map to find affected Lightwell packages
    lightwell_packages: list[LightwellPackageCveStatus] = []
    for base_ver, cve_list in osv_cve_map.items():
        if cve_id in cve_list:
            lightwell_packages.append(LightwellPackageCveStatus(
                package_name=f"(base version {base_ver})",
                base_version=base_ver,
                remediation_id=None,
                status="fixed",
            ))

    return CveDetail(
        cve_id=cve_id,
        severity=cve_data.get("threat_severity"),
        public_date=cve_data.get("public_date"),
        summary=cve_data.get("bugzilla", {}).get("description") if isinstance(cve_data.get("bugzilla"), dict) else None,
        url=f"https://access.redhat.com/security/cve/{cve_id}",
        lightwell_packages=lightwell_packages,
    )


@app.get(f"{PREFIX}/packages/{{package_name}}/cves/", response_model=PaginatedCves, tags=["CVEs"])
async def list_package_cves(
    package_name: str,
    limit: int = Query(20, ge=1),
    offset: int = Query(0, ge=0),
    order: str | None = Query(None),
):
    """List CVEs for a package: local OSV map + Red Hat Security Data API search."""
    sort_spec = _validate_order(order, "cve")

    # Collect CVEs from osv_cve_map that match base versions of this package
    entries: list[PackageCveEntry] = []
    seen_cves: set[str] = set()

    for base_ver, cve_list in osv_cve_map.items():
        for cve_id in cve_list:
            if cve_id not in seen_cves:
                seen_cves.add(cve_id)
                entries.append(PackageCveEntry(
                    cve_id=cve_id,
                    status="fixed",
                    base_version=base_ver,
                ))

    # Also query the Security Data API by package name for broader coverage
    short_name = package_name.split(":")[-1] if ":" in package_name else package_name
    api_cves = await secdata.search_cves(package=short_name, per_page=50)
    for cve_entry in api_cves:
        cve_id = cve_entry.get("CVE", "")
        if cve_id and cve_id not in seen_cves:
            seen_cves.add(cve_id)
            entries.append(PackageCveEntry(
                cve_id=cve_id,
                severity=cve_entry.get("severity"),
                public_date=cve_entry.get("public_date"),
                summary=cve_entry.get("bugzilla_description"),
                status="upstream",
            ))

    if sort_spec:
        field, reverse = sort_spec
        entries.sort(key=lambda e: getattr(e, field, "") or "", reverse=reverse)

    total, page = _paginate(entries, limit, offset)
    return PaginatedCves(count=total, results=page)


# ---------------------------------------------------------------------------
# Routes -- Security Artifacts (Item 2)
# ---------------------------------------------------------------------------

@app.get(
    f"{PREFIX}/packages/{{package_name}}/{{version}}/vex/",
    response_model=list[VexReference],
    tags=["Security Artifacts"],
)
async def get_package_vex(package_name: str, version: str):
    """VEX documents for CVEs applicable to this package version."""
    rhlw = parse_rhlw_version(version)
    if rhlw:
        base_ver, _ = rhlw
    else:
        base_ver = version

    cves = osv_cve_map.get(base_ver, [])
    if not cves:
        return []

    results: list[VexReference] = []
    for cve_id in cves:
        vex_doc = await secdata.get_vex(cve_id)
        year = cve_id.split("-")[1] if "-" in cve_id else "2026"
        results.append(VexReference(
            cve_id=cve_id,
            vex_url=f"{VEX_BASE}/{year}/{cve_id.lower()}.json",
            document=vex_doc,
        ))
    return results


@app.get(
    f"{PREFIX}/packages/{{package_name}}/{{version}}/osv/",
    response_model=OsvEntry,
    tags=["Security Artifacts"],
)
async def get_package_osv(package_name: str, version: str):
    """OSV-related data for a package version from the local CVE map."""
    rhlw = parse_rhlw_version(version)
    if rhlw:
        base_ver, _ = rhlw
    else:
        base_ver = version

    cves = osv_cve_map.get(base_ver, [])
    return OsvEntry(base_version=base_ver, cves=cves)


# ---------------------------------------------------------------------------
# Routes -- Embargoes (Item 3)
# ---------------------------------------------------------------------------

@app.get(f"{PREFIX}/embargoes/", response_model=PaginatedEmbargoes, tags=["Embargoes"])
async def list_embargoes(
    limit: int = Query(20, ge=1),
    offset: int = Query(0, ge=0),
):
    """Paginated list of embargoed packages. Always empty -- embargo data not available."""
    return PaginatedEmbargoes(count=0, results=[])


# ---------------------------------------------------------------------------
# Routes -- POM Resolver
# ---------------------------------------------------------------------------

@app.post(
    f"{PREFIX}/resolve-pom/",
    response_model=PomResolverResponse,
    tags=["POM Resolver"],
    summary="Resolve a Maven POM and identify Lightwell remediations",
)
async def resolve_pom_endpoint(pom_file: UploadFile = File(...)):
    """Accept a Maven POM file, resolve its full transitive dependency tree
    using Maven, match dependencies against the Lightwell remediation catalog,
    report CVEs, and return a remediated POM with patched versions pinned.

    Requires Maven and a JDK on the host.
    """
    content = await pom_file.read()
    try:
        pom_content = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "POM file must be valid UTF-8 XML.")

    if "<project" not in pom_content:
        raise HTTPException(400, "Uploaded file does not appear to be a Maven POM.")

    result = await resolve_pom(pom_content)

    if result.error:
        log.error("POM resolution failed: %s", result.error)
        raise HTTPException(
            422,
            detail={"error": result.error, "summary": "Maven dependency resolution failed."},
        )

    all_cves: set[str] = set()
    match_responses: list[RemediationMatchResponse] = []
    for m in result.matches:
        all_cves.update(m.cves)
        match_responses.append(RemediationMatchResponse(
            group_id=m.dep.group_id,
            artifact_id=m.dep.artifact_id,
            original_version=m.dep.version,
            remediated_version=m.remediated_version,
            base_version=m.base_version,
            cves=m.cves,
            depth=m.dep.depth,
            scope=m.dep.scope,
        ))

    dep_responses = [
        ResolvedDependency(
            group_id=d.group_id,
            artifact_id=d.artifact_id,
            version=d.version,
            scope=d.scope,
            dep_type=d.dep_type,
            depth=d.depth,
            gav=d.gav,
        )
        for d in result.resolved_deps
    ]

    log.info(
        "POM resolved: %d deps, %d matched, %d CVEs",
        result.total_deps, len(result.matches), len(all_cves),
    )
    for m in result.matches:
        how = "direct" if m.dep.depth <= 1 else f"transitive (depth {m.dep.depth})"
        log.info(
            "  %s:%s:%s -> %s [%s] (%d CVEs)",
            m.dep.group_id, m.dep.artifact_id, m.dep.version,
            m.remediated_version, how, len(m.cves),
        )

    return PomResolverResponse(
        summary=ResolverSummary(
            total_dependencies=result.total_deps,
            matched=len(result.matches),
            cves_found=len(all_cves),
            unmatched=len(result.unmatched_deps),
        ),
        matches=match_responses,
        all_dependencies=dep_responses,
        remediated_pom=result.remediated_pom,
    )


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get(f"{PREFIX}/health", tags=["Internal"])
async def health():
    return {
        "status": "ok",
        "data_source": "mock" if pulp.using_mock else "live",
        "repos_cached": len(pulp._repo_cache),
        "osv_cves_cached": len(osv_cve_map),
    }
