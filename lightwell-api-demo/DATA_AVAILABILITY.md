# Lightwell API — Data Availability Assessment

Assessment of data availability for each API section described in the Jira ticket,
mapped against what is currently queryable from Pulp (packages.redhat.com), Red Hat
public data sources, and what is missing entirely.

**Data sources evaluated:**

| Source | Auth | What it provides |
|--------|------|------------------|
| Pulp API (packages.redhat.com) | Basic (TBR) | Repos, content units (Maven/Python), OSV files, content summaries, `pulp_labels`, `pulp_created` timestamps |
| Red Hat Security Data API (access.redhat.com) | None (public) | CVE details, severity, affected products, fix status, CWE references |
| CSAF/VEX repository (security.access.redhat.com) | None (public) | Per-CVE VEX documents with product-level vulnerability status |
| RHTPA (Red Hat Trusted Profile Analyzer) | Internal | `POST /api/v2/vulnerability/analyze` — vulnerability analysis (not SBOM retrieval) |

---

## 1. Package and Repository Queries — ~85%

> List repositories by ecosystem. List packages with filtering by name, version,
> ecosystem, and release date. Return metadata: versions available, release dates,
> which repo each version lives in, and current status.

### Available now

| Field / Capability | Source | Notes |
|--------------------|--------|-------|
| Repository list by ecosystem | Pulp `repositories/{type}/{type}/` | Maven, Python, File repos all enumerable |
| Package list with name filtering | Pulp `content/maven/artifact/`, `content/python/packages/` | `group_id`, `artifact_id`, `name` filters work |
| Version list per package | Pulp content API with `repository_version` scoping | All versions for a given artifact queryable |
| Which repo a version lives in | Pulp `repository_version` parameter | Version scoped to a specific repo |
| `pulp_labels` (build provenance link) | Pulp content API | `source_image` label available on uploaded content |

### Gaps

| Gap | Why | Effort | Notes |
|-----|-----|--------|-------|
| `release_date` (upstream) | Pulp stores `pulp_created` (upload timestamp), not the upstream release date. Upstream dates live in Maven Central / PyPI metadata, not Pulp. | **M** | `pulp_created` is a reasonable proxy for Lightwell's own release cadence. True upstream dates require cross-referencing ecosystem registries. |
| Version filtering | Pulp's content API supports `version` as a filter but not range queries (e.g. "versions after 5.3.18"). | **L** | Client-side filtering on version strings is adequate for Lightwell's catalog size. |
| npm / golang ecosystems | No repos exist in the Lightwell domain yet. | **N/A** | Schema should include these types but they're out of scope until repos are provisioned. |

---

## 2. Embargo Queries — ~0%

> Query packages under embargo. Return embargo timelines: when placed,
> expected lift date, and pre-disclosure information.

### Available now

Nothing. Embargo lifecycle is managed internally by the Lightwell Clearinghouse
Premier system.

### Gaps

| Gap | Why | Effort | Blocker |
|-----|-----|--------|---------|
| Which packages are embargoed | Clearinghouse Premier has no external API or data feed | **H** | Requires Clearinghouse team to expose embargo status |
| `embargo_start_date` | Not stored in Pulp or any queryable system | **H** | Same dependency |
| `expected_lift_date` | Not stored in Pulp or any queryable system | **H** | Same dependency |
| `pre_disclosure_summary` | Not stored in Pulp or any queryable system | **H** | Same dependency |

**This is not an effort problem — it's a data availability problem.** The Clearinghouse
Premier system would need to either:
1. Publish embargo records to a shared data store (e.g., a Pulp repo with structured JSON), or
2. Expose an internal API that the Lightwell API can call.

Until then, the API schema should define the embargo contract but responses will
always return `embargoed: false` and `embargo: null`. This is correctly handled in the
current demo.

---

## 3. CVE Queries — ~60%

> Query a CVE → which Lightwell packages are affected / have a fix / fix in progress.
> Query a package → all CVEs that apply to it with remediation status.

### Available now

| Field / Capability | Source | Notes |
|--------------------|--------|-------|
| CVE details (severity, description, CWEs) | Red Hat Security Data API | Public, comprehensive, covers all Red Hat tracked CVEs |
| Which base versions have a fix | OSV filenames in Pulp (`x_RHLW-CVE-XXXX-XXXXX-{version}.json`) | Maps CVE → base version. Currently parsed at startup. |
| CVE fix status for Red Hat products | Red Hat Security Data API | `affected_release` and `package_state` fields |
| Per-CVE VEX documents | CSAF/VEX repo | Structured fix/affected status per product stream |
| Remediated package versions | Pulp content API | `.rhlw-NNNNN` versions enumerable in remediated repos |

### Gaps

| Gap | Why | Effort | Notes |
|-----|-----|--------|-------|
| "Affected" status for Lightwell packages specifically | Security Data API covers Red Hat products broadly, but doesn't know about Lightwell packages as a distinct product stream. OSV only tells us which packages have fixes, not which are affected but unfixed. | **M** | Requires cross-referencing: enumerate all Lightwell packages, check each against CVE affected components. Could use Security Data API's `package` search. |
| "Fixes in progress" | In-progress fix status lives in PNC / Clearinghouse build pipeline, not in any queryable API. | **H** | Needs pipeline integration. No current data source. |
| Per-rhlw CVE matrix | OSV files map CVEs to the base version (e.g., `5.3.18`), not to specific rhlw iterations. Can't answer "which CVEs were fixed in rhlw-00002 but not rhlw-00001." | **H** | Would need per-iteration OSV records, or integration with RHTPA's analysis endpoint. |
| CVE routes in the API demo | `SecurityDataClient` is built with `get_cve()`, `search_cves()`, `get_vex()` but no routes expose them. | **L** | Pure wiring work — the clients exist, just need routes. |

---

## 4. Security Artifact Retrieval — ~40%

> Retrieve SBOMs, OSV data, build provenance, and VEX for any package version.
> Beyond download, expose queryable data: dependency graphs, vulnerability status,
> build source information.

### Available now

| Artifact | Source | Queryable? | Notes |
|----------|--------|-----------|-------|
| OSV files | Pulp `osv-java-remediated` repo | Partially — filenames are parsed for CVE mapping; raw files downloadable via content URL | Only covers Java remediated packages |
| VEX documents | CSAF/VEX repo (`security.access.redhat.com/data/csaf/v2/vex/`) | Download only (JSON) | Public, no auth. Covers all Red Hat CVEs, not Lightwell-specific. |
| Build provenance (source image) | `pulp_labels.source_image` on content units | Yes, via Pulp content API | Points to Konflux/PNC build image (e.g. `quay.io/redhat-user-workloads/...@sha256:...`) |

### Gaps

| Gap | Why | Effort | Blocker |
|-----|-----|--------|---------|
| SBOMs | Not stored in Pulp. PNC builds may produce SBOMs but they aren't published to any Lightwell-accessible location. | **H** | Needs pipeline to publish SBOMs to a Pulp repo or RHTPA. RHTPA has analysis but not SBOM retrieval by package coordinates. |
| Full SLSA provenance attestations | Only `source_image` label exists. Full attestation chains are in Konflux/Tekton pipeline artifacts, not Pulp. | **H** | Needs Konflux integration to fetch attestations by image reference. |
| Dependency graphs from SBOMs | No SBOMs → no dependency graphs | **H** | Blocked on SBOM availability |
| Queryable OSV data (beyond filenames) | OSV file contents are JSON but not parsed/indexed in Pulp. Would need to fetch and parse each file. | **M** | Files are downloadable; parsing is straightforward but adds latency. Could cache parsed results. |
| Python OSV / non-Java coverage | Only `osv-java-remediated` repo exists | **L** | Would be populated when Python remediation starts |
| VEX route in demo | Client method `get_vex()` exists but no route exposes it | **L** | Pure wiring |

---

## 5. Remediation Changelog — ~30%

> Diff between versions: what patches were applied in rhlw-00002 vs rhlw-00001,
> which CVEs each version addresses, backport vs novel fix classification.

### Available now

| Field / Capability | Source | Notes |
|--------------------|--------|-------|
| rhlw version enumeration | Pulp content API | All `.rhlw-NNNNN` versions for a given base version are listable |
| CVEs addressed per base version | OSV filename mapping | Maps base version → list of CVE IDs |
| Repo version comparison | Pulp `repository_version` API | Can diff content between repo versions (added/removed units) |

### Gaps

| Gap | Why | Effort | Blocker |
|-----|-----|--------|---------|
| Actual patch diffs | Patches are applied in the PNC / Clearinghouse build pipeline. The resulting artifacts are uploaded to Pulp, but the patch source code is not. | **H** | Clearinghouse would need to publish patch metadata alongside the built artifact. |
| Backport vs novel fix classification | Build metadata in Clearinghouse categorizes fixes, but this isn't exposed externally. | **H** | Needs Clearinghouse metadata export. |
| Per-rhlw CVE resolution | OSV maps CVEs to base version, not rhlw iterations. Can't say "rhlw-00002 added fix for CVE-X that rhlw-00001 didn't have." | **H** | Would need per-iteration build records published alongside artifacts. |
| Changelog narrative | No structured change description exists. Would need to be generated from patch + CVE data. | **M** | Depends on patch data existing first. |

**Like embargo, this is fundamentally a data availability problem.** The Clearinghouse
build pipeline produces the data, but doesn't publish it in a machine-readable form
outside the build system. Until that changes, the changelog can only report:
- Which rhlw versions exist (from Pulp)
- Which CVEs the base version has fixes for (from OSV filenames)
- That a remediation happened (implicit from `.rhlw-NNNNN` versioning)

---

## Summary

| API Section | Coverage | Effort to Close | Primary Blocker |
|-------------|----------|-----------------|-----------------|
| Package & Repository Queries | ~85% | **L–M** | `release_date` needs ecosystem registry cross-reference |
| Embargo Queries | ~0% | **H** | Clearinghouse Premier has no external API |
| CVE Queries | ~60% | **M** (wiring) / **H** (full matrix) | Per-rhlw CVE matrix needs pipeline integration |
| Security Artifact Retrieval | ~40% | **H** | SBOMs and provenance not published to Pulp |
| Remediation Changelog | ~30% | **H** | Patch diffs and build metadata not externalized |

### What the demo can show today (with wiring work only)

1. Full repository and package browsing via Pulp
2. CVE lookup via Red Hat Security Data API + OSV cross-reference
3. VEX document retrieval via public CSAF repo
4. Basic remediation enumeration with CVE lists per base version
5. Build image traceability via `pulp_labels.source_image`

### What requires cross-team integration

1. **Embargo data** — Clearinghouse Premier team
2. **SBOMs** — PNC build pipeline or RHTPA team
3. **Patch diffs and fix classification** — Clearinghouse remediation workflow
4. **Per-rhlw CVE resolution tracking** — Per-iteration OSV records or RHTPA integration
5. **Full SLSA provenance** — Konflux team
