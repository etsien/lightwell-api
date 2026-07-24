"""Realistic mock data for the Lightwell API demo.

DISCLAIMER: This module contains fabricated sample data used when the Pulp API
credential lacks admin-level list permissions (HTTP 403).  The repository names,
package naming conventions (.rhlw-NNNNN versions, group_id:artifact_id format),
and OSV filename patterns are modeled after the real Lightwell domain on
packages.redhat.com, but the specific artifacts, versions, and CVE associations
are illustrative and do not represent actual production content.

When this data is active, the /health endpoint returns {"data_source": "mock"}.

The mock data is used for:
  - Repository list and content summaries (REPOS, CONTENT_SUMMARIES)
  - Content units returned by package/version listing endpoints (CONTENT_BY_REPO)
  - OSV file list used to build the CVE-to-base-version map (OSV_FILES)

Fields that remain stubbed regardless of live vs mock data are documented
in app.py's module docstring (embargo, patch diffs, backport classification,
vulnerable_to_cves).
"""

from __future__ import annotations

REPOS = [
    {
        "name": "java-validated",
        "_pulp_type": "maven",
        "latest_version_href": "/api/pulp/lightwell/api/v3/repositories/maven/maven/mock-jv/versions/12/",
    },
    {
        "name": "java-validated-landing",
        "_pulp_type": "maven",
        "latest_version_href": "/api/pulp/lightwell/api/v3/repositories/maven/maven/mock-jvl/versions/14/",
    },
    {
        "name": "java-remediated",
        "_pulp_type": "maven",
        "latest_version_href": "/api/pulp/lightwell/api/v3/repositories/maven/maven/mock-jr/versions/8/",
    },
    {
        "name": "java-remediated-landing",
        "_pulp_type": "maven",
        "latest_version_href": "/api/pulp/lightwell/api/v3/repositories/maven/maven/mock-jrl/versions/10/",
    },
    {
        "name": "python-validated",
        "_pulp_type": "python",
        "latest_version_href": "/api/pulp/lightwell/api/v3/repositories/python/python/mock-pv/versions/6/",
    },
    {
        "name": "python-validated-landing",
        "_pulp_type": "python",
        "latest_version_href": "/api/pulp/lightwell/api/v3/repositories/python/python/mock-pvl/versions/7/",
    },
]

CONTENT_SUMMARIES: dict[str, dict] = {
    "java-validated": {"maven.artifact": {"count": 87412}, "maven.metadata": {"count": 12803}},
    "java-validated-landing": {"maven.artifact": {"count": 87412}, "maven.metadata": {"count": 12803}},
    "java-remediated": {"maven.artifact": {"count": 7831}, "maven.metadata": {"count": 1204}},
    "java-remediated-landing": {"maven.artifact": {"count": 7831}, "maven.metadata": {"count": 1204}},
    "python-validated": {"python.python": {"count": 6623}},
    "python-validated-landing": {"python.python": {"count": 6623}},
}

# Sample content units per repo, covering both validated and remediated packages
MAVEN_VALIDATED_CONTENT = [
    {"group_id": "ch.qos.logback", "artifact_id": "logback-access", "version": "1.1.0", "filename": "logback-access-1.1.0.jar", "pulp_created": "2025-03-15T10:22:00Z", "pulp_labels": {"source_image": "quay.io/redhat-user-workloads/lightwell-poc-tenant/pnc-import/pnc-import@sha256:a1b2c3"}},
    {"group_id": "ch.qos.logback", "artifact_id": "logback-access", "version": "1.2.0", "filename": "logback-access-1.2.0.jar", "pulp_created": "2025-04-01T08:15:00Z", "pulp_labels": {"source_image": "quay.io/redhat-user-workloads/lightwell-poc-tenant/pnc-import/pnc-import@sha256:a1b2c3"}},
    {"group_id": "ch.qos.logback", "artifact_id": "logback-classic", "version": "1.1.0", "filename": "logback-classic-1.1.0.jar", "pulp_created": "2025-03-15T10:22:00Z", "pulp_labels": {}},
    {"group_id": "org.apache.commons", "artifact_id": "commons-lang3", "version": "3.12.0", "filename": "commons-lang3-3.12.0.jar", "pulp_created": "2025-02-20T14:30:00Z", "pulp_labels": {}},
    {"group_id": "org.apache.commons", "artifact_id": "commons-lang3", "version": "3.14.0", "filename": "commons-lang3-3.14.0.jar", "pulp_created": "2025-06-10T09:45:00Z", "pulp_labels": {}},
    {"group_id": "io.netty", "artifact_id": "netty-handler", "version": "4.1.100.Final", "filename": "netty-handler-4.1.100.Final.jar", "pulp_created": "2025-01-08T16:00:00Z", "pulp_labels": {}},
    {"group_id": "io.netty", "artifact_id": "netty-handler", "version": "4.1.108.Final", "filename": "netty-handler-4.1.108.Final.jar", "pulp_created": "2025-05-22T11:30:00Z", "pulp_labels": {}},
    {"group_id": "org.springframework", "artifact_id": "spring-context", "version": "5.3.18", "filename": "spring-context-5.3.18.jar", "pulp_created": "2024-11-05T13:10:00Z", "pulp_labels": {}},
    {"group_id": "org.springframework", "artifact_id": "spring-context", "version": "5.3.27", "filename": "spring-context-5.3.27.jar", "pulp_created": "2025-01-20T07:55:00Z", "pulp_labels": {}},
    {"group_id": "com.fasterxml.jackson.core", "artifact_id": "jackson-databind", "version": "2.15.2", "filename": "jackson-databind-2.15.2.jar", "pulp_created": "2025-02-12T10:00:00Z", "pulp_labels": {}},
]

MAVEN_REMEDIATED_CONTENT = [
    {"group_id": "org.springframework", "artifact_id": "spring-context", "version": "5.3.18.rhlw-00001", "filename": "spring-context-5.3.18.rhlw-00001.jar", "pulp_created": "2025-04-10T14:20:00Z", "pulp_labels": {"source_image": "quay.io/redhat-user-workloads/lightwell-poc-tenant/pnc-import/pnc-import@sha256:d4e5f6"}},
    {"group_id": "org.springframework", "artifact_id": "spring-context", "version": "5.3.18.rhlw-00002", "filename": "spring-context-5.3.18.rhlw-00002.jar", "pulp_created": "2025-05-15T09:45:00Z", "pulp_labels": {"source_image": "quay.io/redhat-user-workloads/lightwell-poc-tenant/pnc-import/pnc-import@sha256:d4e5f6"}},
    {"group_id": "org.springframework", "artifact_id": "spring-context", "version": "5.3.18.rhlw-00003", "filename": "spring-context-5.3.18.rhlw-00003.jar", "pulp_created": "2025-06-20T16:30:00Z", "pulp_labels": {"source_image": "quay.io/redhat-user-workloads/lightwell-poc-tenant/pnc-import/pnc-import@sha256:d4e5f6"}},
    {"group_id": "ch.qos.logback", "artifact_id": "logback-access", "version": "1.1.0.rhlw-00008", "filename": "logback-access-1.1.0.rhlw-00008.jar", "pulp_created": "2025-07-01T12:00:00Z", "pulp_labels": {}},
    {"group_id": "ch.qos.logback", "artifact_id": "logback-access", "version": "1.1.0.rhlw-00012", "filename": "logback-access-1.1.0.rhlw-00012.jar", "pulp_created": "2025-07-10T08:30:00Z", "pulp_labels": {}},
    {"group_id": "io.netty", "artifact_id": "netty-handler", "version": "4.1.100.Final.rhlw-00001", "filename": "netty-handler-4.1.100.Final.rhlw-00001.jar", "pulp_created": "2025-03-28T15:45:00Z", "pulp_labels": {}},
    {"group_id": "com.fasterxml.jackson.core", "artifact_id": "jackson-databind", "version": "2.15.2.rhlw-00001", "filename": "jackson-databind-2.15.2.rhlw-00001.jar", "pulp_created": "2025-04-05T11:10:00Z", "pulp_labels": {}},
    {"group_id": "com.fasterxml.jackson.core", "artifact_id": "jackson-databind", "version": "2.15.2.rhlw-00002", "filename": "jackson-databind-2.15.2.rhlw-00002.jar", "pulp_created": "2025-05-20T13:25:00Z", "pulp_labels": {}},
]

PYTHON_VALIDATED_CONTENT = [
    {"name": "requests", "version": "2.31.0", "filename": "requests-2.31.0.tar.gz", "pulp_created": "2025-02-01T09:00:00Z", "pulp_labels": {}},
    {"name": "requests", "version": "2.28.2", "filename": "requests-2.28.2.tar.gz", "pulp_created": "2024-12-15T14:30:00Z", "pulp_labels": {}},
    {"name": "flask", "version": "3.0.2", "filename": "flask-3.0.2.tar.gz", "pulp_created": "2025-03-10T10:00:00Z", "pulp_labels": {}},
    {"name": "django", "version": "4.2.16", "filename": "Django-4.2.16.tar.gz", "pulp_created": "2025-04-22T16:45:00Z", "pulp_labels": {}},
    {"name": "cryptography", "version": "42.0.5", "filename": "cryptography-42.0.5.tar.gz", "pulp_created": "2025-01-30T08:20:00Z", "pulp_labels": {}},
    {"name": "urllib3", "version": "2.2.1", "filename": "urllib3-2.2.1.tar.gz", "pulp_created": "2025-02-18T11:15:00Z", "pulp_labels": {}},
]

CONTENT_BY_REPO: dict[str, list[dict]] = {
    "java-validated": MAVEN_VALIDATED_CONTENT,
    "java-validated-landing": MAVEN_VALIDATED_CONTENT,
    "java-remediated": MAVEN_REMEDIATED_CONTENT,
    "java-remediated-landing": MAVEN_REMEDIATED_CONTENT,
    "python-validated": PYTHON_VALIDATED_CONTENT,
    "python-validated-landing": PYTHON_VALIDATED_CONTENT,
}

OSV_FILES = [
    {"relative_path": "x_RHLW-CVE-2024-38808-5.3.18.json", "pulp_labels": {}},
    {"relative_path": "x_RHLW-CVE-2023-34055-5.3.18.json", "pulp_labels": {}},
    {"relative_path": "x_RHLW-CVE-2024-22262-5.3.18.json", "pulp_labels": {}},
    {"relative_path": "x_RHLW-CVE-2024-12798-1.1.0.json", "pulp_labels": {}},
    {"relative_path": "x_RHLW-CVE-2023-5022-1.1.0.json", "pulp_labels": {}},
    {"relative_path": "x_RHLW-CVE-2023-44487-4.1.100.Final.json", "pulp_labels": {}},
    {"relative_path": "x_RHLW-CVE-2024-29025-4.1.100.Final.json", "pulp_labels": {}},
    {"relative_path": "x_RHLW-CVE-2022-42003-2.15.2.json", "pulp_labels": {}},
    {"relative_path": "x_RHLW-CVE-2023-35116-2.15.2.json", "pulp_labels": {}},
]
