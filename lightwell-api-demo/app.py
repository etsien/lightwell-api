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
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query

from backends import (
    CONTENT_ENDPOINTS,
    PulpClient,
    SecurityDataClient,
    package_name_from_content,
    package_version_from_content,
    parse_rhlw_version,
    security_level_from_name,
)
from schemas import (
    Package,
    PackageType,
    PackageVersion,
    PaginatedPackages,
    PaginatedPackageVersions,
    PaginatedRemediations,
    PaginatedRepositories,
    Remediation,
    RemediationChange,
    RemediationSummary,
    Repository,
    SecurityLevel,
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
            versions.append(PackageVersion(
                name=name,
                security_level=sec_level,
                type=api_type,
                version=ver,
                latest_remediation=remediation,
            ))
    return versions


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


def _match_filters(
    pkg: PackageVersion,
    *,
    type_filter: PackageType | None,
    name_filter: str | None,
    repo_filter: str | None,
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


# ---------------------------------------------------------------------------
# Routes — Repositories
# ---------------------------------------------------------------------------

@app.get(f"{PREFIX}/repositories/", response_model=PaginatedRepositories, tags=["Repositories"])
async def list_repositories(
    limit: int = Query(20, ge=1),
    offset: int = Query(0, ge=0),
    order: str | None = Query(None),
    type: PackageType | None = Query(None),
):
    repos = await pulp.list_repos()
    results: list[Repository] = []

    for r in repos:
        rtype = _repo_type(r)
        api_type = _api_type(rtype)
        if type and api_type != type:
            continue
        name = r["name"]
        summary = await pulp.get_repo_version_summary(r)
        content_count = sum(v.get("count", 0) for v in summary.values())
        results.append(Repository(
            name=name,
            security_level=SecurityLevel(security_level_from_name(name)),
            type=api_type,
            packages_count=content_count,
            versions_count=content_count,
            remediations_count=content_count if "remediated" in name else 0,
        ))

    if order:
        parts = order.split()
        field = parts[0] if parts else "name"
        reverse = len(parts) > 1 and parts[1].lower() == "desc"
        results.sort(key=lambda r: getattr(r, field, ""), reverse=reverse)

    total, page = _paginate(results, limit, offset)
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

    # Fetch a generous page from Pulp, then deduplicate client-side
    data = await pulp.list_content(repository_name, limit=500, offset=0, **filters)
    units = data.get("results", [])
    packages = _deduplicate_packages(units, rtype, sec_level, api_type)

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

    return PackageVersion(
        name=package_name,
        security_level=sec_level,
        type=api_type,
        version=version,
        latest_remediation=remediation,
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
    repo = await pulp.get_repo(repository_name)
    if not repo:
        raise HTTPException(404, f"Repository '{repository_name}' not found")

    rtype = _repo_type(repo)
    sec_level = SecurityLevel(security_level_from_name(repository_name))

    units = await pulp.list_all_content_versions(repository_name, package_name, rtype, limit=500)

    # Find all rhlw versions whose base matches the requested version,
    # or if the requested version is itself an rhlw version, list that one.
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

    remediations.sort(key=lambda r: r.id, reverse=True)
    total, page = _paginate(remediations, limit, offset)
    return PaginatedRemediations(count=total, results=page)


# ---------------------------------------------------------------------------
# Routes — Packages (cross-repository)
# ---------------------------------------------------------------------------

@app.get(f"{PREFIX}/packages/", response_model=PaginatedPackages, tags=["Packages"])
async def list_packages(
    limit: int = Query(20, ge=1),
    offset: int = Query(0, ge=0),
    order: str | None = Query(None),
    type: PackageType | None = Query(None),
    name: str | None = Query(None),
    security_level: SecurityLevel | None = Query(None),
):
    repos = await pulp.list_repos()
    all_packages: list[Package] = []
    seen: set[tuple[str, str, str]] = set()

    for r in repos:
        rtype = _repo_type(r)
        api_type = _api_type(rtype)
        if type and api_type != type:
            continue
        sec_level = SecurityLevel(security_level_from_name(r["name"]))
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

        data = await pulp.list_content(r["name"], limit=200, **filters)
        for unit in data.get("results", []):
            pkg_name = package_name_from_content(unit, rtype)
            key = (pkg_name, sec_level.value, api_type.value)
            if pkg_name and key not in seen:
                seen.add(key)
                all_packages.append(Package(name=pkg_name, security_level=sec_level, type=api_type))

    total, page = _paginate(all_packages, limit, offset)
    return PaginatedPackages(count=total, results=page)


# ---------------------------------------------------------------------------
# Routes — Package Versions (cross-repository)
# ---------------------------------------------------------------------------

@app.get(f"{PREFIX}/package_versions/", response_model=PaginatedPackageVersions, tags=["Package Versions"])
async def list_package_versions(
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
    repos = await pulp.list_repos()
    all_versions: list[PackageVersion] = []

    seen_versions: set[tuple[str, str, str]] = set()
    for r in repos:
        repo_name = r["name"]
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

        data = await pulp.list_content(repo_name, limit=200, **filters)
        versions = _deduplicate_versions(data.get("results", []), rtype, sec_level, api_type)

        for v in versions:
            dedup_key = (v.name, v.version, v.security_level.value)
            if dedup_key in seen_versions:
                continue
            seen_versions.add(dedup_key)
            if _match_filters(
                v,
                type_filter=type,
                name_filter=name,
                repo_filter=repository,
                sec_level_filter=security_level,
                embargoed_filter=embargoed,
                resolves_cve=resolves_cve_id,
                vulnerable_to_cve=vulnerable_to_cve_id,
            ):
                all_versions.append(v)

    total, page = _paginate(all_versions, limit, offset)
    return PaginatedPackageVersions(count=total, results=page)


# ---------------------------------------------------------------------------
# Routes — Remediations (cross-repository)
# ---------------------------------------------------------------------------

@app.get(f"{PREFIX}/remediations/", response_model=PaginatedRemediations, tags=["Remediations"])
async def list_remediations(
    limit: int = Query(20, ge=1),
    offset: int = Query(0, ge=0),
    order: str | None = Query(None),
    name: str | None = Query(None),
    version: str | None = Query(None),
    type: PackageType | None = Query(None),
    embargoed: bool | None = Query(None),
):
    repos = await pulp.list_repos()
    all_remediations: list[Remediation] = []
    seen_global: set[tuple[str, str]] = set()

    for r in repos:
        repo_name = r["name"]
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

        data = await pulp.list_content(repo_name, limit=200, **filters)
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

    all_remediations.sort(key=lambda r: r.id, reverse=True)
    total, page = _paginate(all_remediations, limit, offset)
    return PaginatedRemediations(count=total, results=page)


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
