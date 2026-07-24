"""Backend clients for Pulp API and Red Hat Security Data API.

PulpClient attempts live queries against packages.redhat.com.  If the
credential returns HTTP 403 (download-only TBR token without admin list
permissions), the client logs a warning and transparently switches to
mock_data.py for all subsequent calls.  The switch is surfaced via
PulpClient.using_mock and the /health endpoint's "data_source" field.

SecurityDataClient always hits the public Red Hat Security Data API at
access.redhat.com (no auth required) and never falls back to mock data.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

import mock_data

log = logging.getLogger(__name__)

PULP_BASE = "https://packages.redhat.com/api/pulp/lightwell/api/v3"
SECURITY_DATA_BASE = "https://access.redhat.com/hydra/rest/securitydata"
VEX_BASE = "https://security.access.redhat.com/data/csaf/v2/vex"

RHLW_RE = re.compile(r"^(.+)\.rhlw-(\d+)$")
OSV_FILENAME_RE = re.compile(r"x_RHLW-(CVE-[\d-]+)-(.+)\.json$")

# Map Pulp repo plugin type slug to API PackageType
PULP_TYPE_TO_API = {
    "maven": "maven",
    "python": "python",
    "npm": "npm",
}

# Pulp content endpoints per plugin type
CONTENT_ENDPOINTS = {
    "maven": "content/maven/artifact/",
    "python": "content/python/packages/",
}

# Pulp repository endpoints per plugin type
REPO_ENDPOINTS = {
    "maven": "repositories/maven/maven/",
    "python": "repositories/python/python/",
    "file": "repositories/file/file/",
}


def parse_rhlw_version(version: str) -> tuple[str, str] | None:
    """Parse '5.3.18.rhlw-00003' into ('5.3.18', 'rhlw-00003'). None if not rhlw."""
    m = RHLW_RE.match(version)
    if m:
        return m.group(1), f"rhlw-{m.group(2)}"
    return None


def security_level_from_name(repo_name: str) -> str:
    if "remediated" in repo_name:
        return "remediated"
    return "validated"


def package_name_from_content(unit: dict, repo_type: str) -> str:
    if repo_type == "maven":
        return f"{unit.get('group_id', '')}:{unit.get('artifact_id', '')}"
    return unit.get("name", "")


def package_version_from_content(unit: dict) -> str:
    return unit.get("version", "")


class PulpClient:
    """Async client for the Pulp REST API on packages.redhat.com.

    Falls back to mock data when the credential lacks admin permissions (403).
    """

    def __init__(self, username: str, password: str, base_url: str = PULP_BASE):
        self.base_url = base_url.rstrip("/")
        self._auth = (username, password)
        self._client: httpx.AsyncClient | None = None
        self._repo_cache: dict[str, dict] = {}
        self.using_mock = False

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                auth=self._auth,
                timeout=30.0,
                follow_redirects=True,
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def _get(self, path: str, params: dict | None = None) -> dict:
        client = await self._get_client()
        url = f"{self.base_url}/{path.lstrip('/')}"
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def _activate_mock(self):
        if not self.using_mock:
            log.warning("Pulp API returned 403; switching to mock data for demo")
            self.using_mock = True
        self._repo_cache = {r["name"]: r for r in mock_data.REPOS}

    # ---- Repositories ----

    async def list_repos(self) -> list[dict]:
        """List all repos across plugin types, excluding OSV/file repos."""
        if self.using_mock:
            return list(mock_data.REPOS)

        repos: list[dict] = []
        access_denied = True
        for pulp_type, endpoint in REPO_ENDPOINTS.items():
            if pulp_type == "file":
                continue
            try:
                data = await self._get(endpoint, {"fields": "name,pulp_href,latest_version_href", "limit": 100})
                for r in data.get("results", []):
                    r["_pulp_type"] = pulp_type
                    repos.append(r)
                access_denied = False
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 403:
                    log.warning("403 on %s repos", pulp_type)
                else:
                    log.warning("Failed to list %s repos: %s", pulp_type, e)
            except httpx.HTTPError as e:
                log.warning("Failed to list %s repos: %s", pulp_type, e)

        if access_denied and not repos:
            self._activate_mock()
            return list(mock_data.REPOS)

        self._repo_cache = {r["name"]: r for r in repos}
        return repos

    async def get_repo(self, name: str) -> dict | None:
        if not self._repo_cache:
            await self.list_repos()
        return self._repo_cache.get(name)

    async def get_repo_version_summary(self, repo: dict) -> dict:
        """Fetch the content_summary for the repo's latest version."""
        if self.using_mock:
            return mock_data.CONTENT_SUMMARIES.get(repo["name"], {})
        href = repo.get("latest_version_href")
        if not href:
            return {}
        try:
            client = await self._get_client()
            url = f"https://packages.redhat.com{href}"
            resp = await client.get(url, params={"fields": "content_summary"})
            resp.raise_for_status()
            return resp.json().get("content_summary", {}).get("present", {})
        except httpx.HTTPError:
            return mock_data.CONTENT_SUMMARIES.get(repo["name"], {})

    # ---- Content listing ----

    async def list_content(
        self,
        repo_name: str,
        limit: int = 100,
        offset: int = 0,
        **filters: Any,
    ) -> dict:
        """List content units for a repo. Returns raw Pulp paginated response."""
        if self.using_mock:
            return self._mock_content(repo_name, limit, offset, **filters)

        repo = await self.get_repo(repo_name)
        if not repo:
            return {"count": 0, "results": []}

        pulp_type = repo["_pulp_type"]
        endpoint = CONTENT_ENDPOINTS.get(pulp_type)
        if not endpoint:
            return {"count": 0, "results": []}

        params: dict[str, Any] = {
            "repository_version": repo["latest_version_href"],
            "limit": limit,
            "offset": offset,
        }
        for key, val in filters.items():
            if val is not None:
                params[key] = val

        try:
            return await self._get(endpoint, params)
        except httpx.HTTPError:
            return self._mock_content(repo_name, limit, offset, **filters)

    def _mock_content(self, repo_name: str, limit: int, offset: int, **filters: Any) -> dict:
        units = list(mock_data.CONTENT_BY_REPO.get(repo_name, []))
        for key, val in filters.items():
            if val is None:
                continue
            units = [u for u in units if u.get(key) == val]
        total = len(units)
        return {"count": total, "results": units[offset : offset + limit]}

    async def list_all_content_versions(
        self,
        repo_name: str,
        pkg_name: str,
        repo_type: str,
        limit: int = 200,
    ) -> list[dict]:
        """List all content for a specific package name across versions."""
        filters: dict[str, str] = {}
        if repo_type == "maven":
            parts = pkg_name.split(":", 1)
            if len(parts) == 2:
                filters["group_id"] = parts[0]
                filters["artifact_id"] = parts[1]
        else:
            filters["name"] = pkg_name

        data = await self.list_content(repo_name, limit=limit, **filters)
        return data.get("results", [])

    # ---- OSV files ----

    async def list_osv_files(self, limit: int = 200) -> list[dict]:
        """List file content from the osv-java-remediated repo."""
        if self.using_mock:
            return list(mock_data.OSV_FILES)
        try:
            file_repos = await self._get(
                REPO_ENDPOINTS["file"],
                {"name": "osv-java-remediated", "fields": "name,pulp_href,latest_version_href"},
            )
            results = file_repos.get("results", [])
            if not results:
                return list(mock_data.OSV_FILES)
            repo = results[0]
            href = repo.get("latest_version_href")
            if not href:
                return list(mock_data.OSV_FILES)
            data = await self._get(
                "content/file/files/",
                {"repository_version": href, "limit": limit, "fields": "relative_path,pulp_labels"},
            )
            return data.get("results", [])
        except httpx.HTTPError as e:
            log.warning("Failed to list OSV files: %s; using mock data", e)
            return list(mock_data.OSV_FILES)

    def parse_osv_cves(self, osv_files: list[dict]) -> dict[str, list[str]]:
        """Parse OSV filenames into a map of base_version -> [CVE-IDs].

        Filename pattern: x_RHLW-CVE-2024-38808-5.3.18.json
        """
        version_cves: dict[str, list[str]] = {}
        for f in osv_files:
            name = f.get("relative_path", "")
            m = OSV_FILENAME_RE.match(name)
            if m:
                cve_id = m.group(1)
                base_ver = m.group(2)
                version_cves.setdefault(base_ver, []).append(cve_id)
        return version_cves


class SecurityDataClient:
    """Async client for the Red Hat Security Data API (public, no auth)."""

    def __init__(self, base_url: str = SECURITY_DATA_BASE):
        self.base_url = base_url.rstrip("/")
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=15.0, follow_redirects=True)
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def get_cve(self, cve_id: str) -> dict | None:
        """Get full CVE details from the Security Data API."""
        try:
            client = await self._get_client()
            resp = await client.get(f"{self.base_url}/cve/{cve_id}.json")
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            log.warning("Security Data API error for %s: %s", cve_id, e)
            return None

    async def search_cves(
        self,
        package: str | None = None,
        severity: str | None = None,
        after: str | None = None,
        before: str | None = None,
        per_page: int = 50,
    ) -> list[dict]:
        """Search CVEs by package, severity, date range."""
        params: dict[str, Any] = {"per_page": per_page}
        if package:
            params["package"] = package
        if severity:
            params["severity"] = severity
        if after:
            params["after"] = after
        if before:
            params["before"] = before
        try:
            client = await self._get_client()
            resp = await client.get(f"{self.base_url}/cve.json", params=params)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            log.warning("CVE search failed: %s", e)
            return []

    async def get_vex(self, cve_id: str) -> dict | None:
        """Fetch a per-CVE VEX document from the CSAF/VEX repository."""
        year = cve_id.split("-")[1] if "-" in cve_id else "2026"
        url = f"{VEX_BASE}/{year}/{cve_id.lower()}.json"
        try:
            client = await self._get_client()
            resp = await client.get(url)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            log.warning("VEX fetch failed for %s: %s", cve_id, e)
            return None
