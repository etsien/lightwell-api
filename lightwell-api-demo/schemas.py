"""Pydantic models matching the Lightwell Package Security API 0.1.0 spec."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class SecurityLevel(str, Enum):
    validated = "validated"
    remediated = "remediated"


class PackageType(str, Enum):
    python = "python"
    maven = "maven"
    npm = "npm"
    golang = "golang"


# ---- Resource models ----

class Repository(BaseModel):
    name: str
    security_level: SecurityLevel
    type: PackageType
    packages_count: int
    versions_count: int
    remediations_count: int


class Package(BaseModel):
    name: str
    security_level: SecurityLevel
    type: PackageType


class Embargo(BaseModel):
    embargo_start_date: datetime
    expected_lift_date: datetime
    pre_disclosure_summary: str


class RemediationSummary(BaseModel):
    id: str
    resolved_cves: list[str]
    vulnerable_to_cves: list[str]
    embargoed: bool
    embargo: Embargo | None = None


class PackageVersion(BaseModel):
    name: str
    security_level: SecurityLevel
    type: PackageType
    version: str
    latest_remediation: RemediationSummary | None = None
    release_date: datetime | None = None
    repository: str | None = None


class RemediationChange(BaseModel):
    redhat_identifier: str
    cve: str
    patch: str
    backport: bool
    novel_fix: bool


class Remediation(BaseModel):
    name: str
    security_level: SecurityLevel
    version: str
    id: str
    addressed_cves: list[str]
    vulnerable_to_cves: list[str]
    embargoed: bool
    embargo: Embargo | None = None
    changes: list[RemediationChange]


# ---- CVE / Security models ----

class LightwellPackageCveStatus(BaseModel):
    """A Lightwell package affected by or remediated for a CVE."""
    package_name: str
    base_version: str
    remediation_id: str | None = None
    status: str = "fixed"


class CveDetail(BaseModel):
    """CVE details combined with Lightwell remediation status."""
    cve_id: str
    severity: str | None = None
    public_date: str | None = None
    summary: str | None = None
    url: str | None = None
    lightwell_packages: list[LightwellPackageCveStatus] = []


class PackageCveEntry(BaseModel):
    """A CVE entry associated with a specific package."""
    cve_id: str
    severity: str | None = None
    public_date: str | None = None
    summary: str | None = None
    status: str = "fixed"
    base_version: str | None = None


class VexReference(BaseModel):
    """Reference to a VEX document for a CVE."""
    cve_id: str
    vex_url: str | None = None
    document: dict | None = None


class OsvEntry(BaseModel):
    """OSV-related data for a package version."""
    base_version: str
    cves: list[str] = []


class EmbargoEntry(BaseModel):
    """Placeholder for an embargoed package entry."""
    package_name: str
    embargo: Embargo


# ---- Paginated wrappers ----

class PaginatedRepositories(BaseModel):
    count: int
    results: list[Repository]


class PaginatedPackages(BaseModel):
    count: int
    results: list[Package]


class PaginatedPackageVersions(BaseModel):
    count: int
    results: list[PackageVersion]


class PaginatedRemediations(BaseModel):
    count: int
    results: list[Remediation]


class PaginatedCves(BaseModel):
    count: int
    results: list[PackageCveEntry]


class PaginatedEmbargoes(BaseModel):
    count: int
    results: list[EmbargoEntry]


# ---- POM Resolver models ----

class ResolvedDependency(BaseModel):
    group_id: str
    artifact_id: str
    version: str
    scope: str
    dep_type: str
    depth: int
    gav: str

class RemediationMatchResponse(BaseModel):
    group_id: str
    artifact_id: str
    original_version: str
    remediated_version: str
    base_version: str
    cves: list[str]
    depth: int
    scope: str

class ResolverSummary(BaseModel):
    total_dependencies: int
    matched: int
    cves_found: int
    unmatched: int

class PomResolverResponse(BaseModel):
    summary: ResolverSummary
    matches: list[RemediationMatchResponse]
    all_dependencies: list[ResolvedDependency]
    remediated_pom: str
    error: str | None = None
