# Lightwell API — Data Availability Assessment

Assessment of data availability for each API section described in the Jira ticket,
mapped against what is currently queryable from Pulp (packages.redhat.com), Red Hat
public data sources, and what is missing entirely.

**Data sources evaluated:**

| Source | Auth | What it provides |
|--------|------|------------------|
| Pulp API (packages.redhat.com) | Basic (TBR) | Repos, content units (Maven/Python), OSV files, content summaries, `pulp_labels`, `pulp_created` timestamps |
| Pulp content app (packages.redhat.com) | Basic (TBR) | Direct file download: JARs, POMs, **CycloneDX SBOMs**, **Sigstore provenance**, sources, signatures, checksums |
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

## 4. Security Artifact Retrieval — ~80%

> Retrieve SBOMs, OSV data, build provenance, and VEX for any package version.
> Beyond download, expose queryable data: dependency graphs, vulnerability status,
> build source information.

**UPDATE:** CycloneDX SBOMs and Sigstore SLSA provenance attestations are stored in
Pulp as Maven artifacts alongside the JARs. They are downloadable via the content app
using the same TBR credentials used for package access.

### Artifact inventory per remediated package version

Each `.rhlw-NNNNN` version in Pulp includes the following files:

| File pattern | Format | Contents |
|---|---|---|
| `{artifact}-{version}.cyclonedx.json` | CycloneDX 1.6 | Full SBOM: ~1100 components, ~1100 dependency edges, build metadata |
| `{artifact}-{version}.provenance.sigstore.json` | DSSE envelope / in-toto v1 | SLSA provenance: PNC build name, git source URI + commit, 1104 resolved dependencies, builder ID (PNC 3.5.6), ~90 subjects, `BUILD_CATEGORY=LIGHTWELL` |
| `{artifact}-{version}.jar` | JAR | The built artifact |
| `{artifact}-{version}.pom` | Maven POM | Project metadata and declared dependencies |
| `{artifact}-{version}-sources.jar` | JAR | Source code |
| `{artifact}-{version}-javadoc.jar` | JAR | Javadoc |
| `*.asc` | PGP/ASCII armor | Detached signature for each of the above |
| `*.sha1`, `*.sha256`, `*.md5` | Checksum | For each of the above |

### Available now

| Artifact | Source | Queryable? | Notes |
|----------|--------|-----------|-------|
| CycloneDX SBOMs | Pulp content app (`*.cyclonedx.json`) | **Yes** — JSON, downloadable and parseable. Contains full dependency graph (components + dependencies arrays). | CycloneDX 1.6 spec. ~1100 components per SBOM for a package like spring-context. |
| SLSA provenance | Pulp content app (`*.provenance.sigstore.json`) | **Yes** — DSSE envelope with base64 in-toto payload. Decode to get build source, git commit, resolved dependencies, builder identity. | `buildType: https://project-ncl.github.io/slsa-pnc-buildtypes/workflow/v1`. Builder: PNC 3.5.6. |
| Dependency graphs | Derived from CycloneDX SBOM `dependencies` array | **Yes** — parse SBOM JSON | ~1100 dependency edges per SBOM |
| Build source info | Provenance payload `resolvedDependencies[0]` | **Yes** — git URI + commit hash | e.g., `git+https://gitlab.cee.redhat.com/lightwell/lightwell-builds/...` |
| OSV files | Pulp `osv-java-remediated` repo | Partially — filenames parsed for CVE mapping; raw JSON downloadable | Only covers Java remediated packages |
| VEX documents | CSAF/VEX repo (`security.access.redhat.com/data/csaf/v2/vex/`) | Download only (JSON) | Public, no auth. Covers all Red Hat CVEs. |

### Download URL pattern

SBOMs and provenance are regular Maven artifacts accessible via:

```
https://packages.redhat.com/api/pulp-content/lightwell/java/remediated/{group_path}/{artifact_id}/{version}/{filename}
```

Example:
```
.../java/remediated/org/springframework/spring-context/5.3.18.rhlw-00010/spring-context-5.3.18.rhlw-00010.cyclonedx.json
```

### Remaining gaps

| Gap | Why | Effort | Notes |
|-----|-----|--------|---------|
| SBOM queryable endpoint | SBOMs exist but no API route fetches/parses them yet | **M** | Download the `.cyclonedx.json` via content URL, parse, and return structured dependency data. Needs caching for performance. |
| Provenance queryable endpoint | Provenance exists but no API route decodes/returns it yet | **M** | Download `.provenance.sigstore.json`, decode DSSE payload, return structured build info. |
| Queryable OSV data (beyond filenames) | OSV file contents not parsed/indexed | **M** | Files are downloadable JSON; parsing is straightforward but adds latency. |
| Python / non-Java coverage | Only Java remediated packages have SBOMs currently | **L** | Would be populated when Python remediation starts |
| Validated package SBOMs | Validated (non-rhlw) packages may not have CycloneDX files | **L** | PNC builds produce them; depends on whether validated builds go through PNC |

---

## 5. Remediation Changelog — ~55%

> Diff between versions: what patches were applied in rhlw-00002 vs rhlw-00001,
> which CVEs each version addresses, backport vs novel fix classification.

**UPDATE:** The OSV files contain rich structured data beyond their filenames, and
the provenance attestations provide per-iteration git commit traceability.

### OSV file internal structure (discovered)

Each OSV JSON file contains:

```json
{
  "id": "x_RHLW-CVE-2024-38808-5.3.18",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"}],
  "summary": "CVE-2024-38808: Spring Expression DoS Vulnerability",
  "details": "...",
  "affected": [{
    "package": {"ecosystem": "Maven", "name": "org.springframework:spring-expression"},
    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "5.3.18.rhlw-00010"}]}]
  }],
  "database_specific": {
    "lightwell": {
      "source": "lightwell-pipeline",
      "backport_base_version": "5.3.18",
      "golden_pipeline_id": "16367840"
    }
  }
}
```

### Available now

| Field / Capability | Source | Notes |
|--------------------|--------|-------|
| rhlw version enumeration | Pulp content API | All `.rhlw-NNNNN` versions for a given base version are listable |
| Cumulative CVE list per base version | OSV file contents (`affected[].ranges[].events[].fixed`) | Lists all CVEs fixed as of the latest rhlw iteration |
| Affected sub-component per CVE | OSV `affected[].package.name` | Identifies the specific artifact within the build (e.g. `spring-expression` vs `spring-webmvc`) |
| Backport confirmation | OSV `database_specific.lightwell.backport_base_version` | Confirms the fix is a backport from the base version |
| PNC build pipeline linkage | OSV `database_specific.lightwell.golden_pipeline_id` | Links each CVE fix to a specific PNC build |
| Git source + commit per rhlw | Provenance `resolvedDependencies[0]` | Each rhlw iteration has a distinct git commit (e.g. `1a5ab4b...` for rhlw-00009, `01db8fc...` for rhlw-00010) |
| SBOM component diff between iterations | CycloneDX SBOM comparison | Diffing SBOMs shows exactly which components changed between rhlw-00009 and rhlw-00010 |
| CVE severity and details | OSV `severity` + Red Hat Security Data API | CVSS v3 scores available per CVE |
| Upload timestamp per version | Pulp `pulp_created` | When each rhlw iteration was uploaded |

### What can be constructed from existing data

A meaningful changelog can be built by combining these sources:

1. **"What CVEs are addressed?"** — Parse all OSV files for the base version. Each
   file identifies the CVE, the affected component, severity, and that the fix is
   a backport. (Available now, effort **L**.)

2. **"What changed between rhlw-00009 and rhlw-00010?"** — Diff the CycloneDX SBOMs
   to see component version changes. Cross-reference against the CVE list to see
   which new CVE fixes appeared. (Available now, effort **M**.)

3. **"Is this a backport or novel fix?"** — `backport_base_version` in the OSV
   `database_specific.lightwell` section confirms backport status. All current
   remediation is backport-based. (Available now, effort **L**.)

4. **"Link to the build"** — `golden_pipeline_id` links to the PNC build.
   Provenance provides the git commit. (Available now, effort **L**.)

### Remaining gaps

These gaps require the Clearinghouse build pipeline to publish additional
pre-computed data. The Lightwell API is a thin read layer and should not
reach into internal systems (GitLab, PNC) to compute this at query time.

| Gap | What the pipeline should publish | Effort (pipeline) | Notes |
|-----|----------------------------------|-------------------|-------|
| Per-iteration CVE introduction | Per-rhlw OSV snapshots or a manifest listing which CVEs each iteration addressed. Currently all OSV files reference the latest rhlw as the `fixed` version. | **M** | Could be a JSON sidecar file per rhlw iteration (e.g. `spring-context-5.3.18.rhlw-00010.changelog.json`) or richer `events` arrays in OSV. |
| Patch diff summaries | A structured summary of what changed between iterations (files modified, lines changed, CVE references). Git commits exist in provenance but the repo is internal. | **M** | Pipeline has GitLab access and can compute diffs at build time, publishing a summary alongside the artifact. |
| Novel fix identification | A flag or field distinguishing backports from original patches. Currently all fixes have `backport_base_version` set. | **L** | Schema is ready; data will appear when non-backport fixes are produced. |
| Changelog narrative | Human-readable or auto-generated change description per iteration. | **L** | Can be generated in the pipeline from CVE summaries + patch metadata. |

---

## Summary

| API Section | Coverage | Effort to Close | Primary Blocker |
|-------------|----------|-----------------|-----------------|
| Package & Repository Queries | ~85% | **L–M** | `release_date` needs ecosystem registry cross-reference |
| Embargo Queries | ~0% | **H** | Clearinghouse Premier has no external API |
| CVE Queries | ~60% | **M** (wiring) / **H** (full matrix) | Per-rhlw CVE matrix needs pipeline integration |
| Security Artifact Retrieval | **~80%** | **M** | SBOMs and provenance exist in Pulp; need API routes to fetch/parse them |
| Remediation Changelog | **~55%** | **M** | OSV internals + provenance commits cover CVE-to-fix mapping and backport status; per-iteration CVE tracking and patch diffs need git access |

### What the demo can show today (with wiring work only)

1. Full repository and package browsing via Pulp
2. CVE lookup via Red Hat Security Data API + OSV cross-reference
3. VEX document retrieval via public CSAF repo
4. Basic remediation enumeration with CVE lists per base version
5. Build image traceability via `pulp_labels.source_image`
6. **CycloneDX SBOM download and dependency graph extraction** (1100 components per SBOM)
7. **SLSA provenance with full PNC build metadata** (git source, commit, builder, resolved deps)

### What requires cross-team integration

1. **Embargo data** — Clearinghouse Premier team (no workaround; needs an API or data feed)
2. **Per-iteration changelog data** — Clearinghouse build pipeline should publish pre-computed artifacts: per-rhlw CVE introduction mapping, patch diff summaries, and changelog narratives. The API is a thin read layer and should not compute these at query time by reaching into internal GitLab or PNC.

### Previously thought missing, now confirmed available

1. ~~**SBOMs**~~ — CycloneDX 1.6 JSON files stored alongside JARs in Pulp Maven repos
2. ~~**SLSA provenance**~~ — Sigstore DSSE envelopes with in-toto v1 payloads, PNC buildtype, stored alongside JARs
