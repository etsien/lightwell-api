# Lightwell API Demo

Demo server implementing the Lightwell Package Security API 0.1.0 spec,
including a POM auto-resolver that identifies vulnerable transitive
dependencies and produces a remediated `pom.xml` with Lightwell patches.

## Prerequisites

- Python 3.12+
- Maven 3.9+ and a JDK (for the POM resolver)
- Lightwell TBR credentials (optional -- falls back to mock data without them)

## Setup

```bash
cd lightwell-api-demo

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file with credentials (or skip this to use mock data):

```bash
cat > .env << 'EOF'
LIGHTWELL_TBR_USER=your-username
LIGHTWELL_TBR_PASS=your-password
EOF
```

## Start the server

```bash
uvicorn app:app --reload --port 8000
```

The API is available at `http://localhost:8000/api/lightwell/v0.1/`.
Interactive docs at `http://localhost:8000/docs`.

Check data source (live Pulp vs mock):

```bash
curl -s http://localhost:8000/api/lightwell/v0.1/health | jq .
```

## POM Resolver Demo

The resolver takes a customer's Maven POM, resolves the full transitive
dependency tree via `mvn dependency:tree`, matches against the Lightwell
remediation catalog, reports CVEs, and returns a patched POM.

### 1. Resolve the sample POM

```bash
curl -s -X POST http://localhost:8000/api/lightwell/v0.1/resolve-pom/ \
  -F "pom_file=@sample-customer-pom.xml" \
  | jq .
```

### 2. View just the summary

```bash
curl -s -X POST http://localhost:8000/api/lightwell/v0.1/resolve-pom/ \
  -F "pom_file=@sample-customer-pom.xml" \
  | jq '.summary'
```

### 3. Extract the remediated POM

```bash
curl -s -X POST http://localhost:8000/api/lightwell/v0.1/resolve-pom/ \
  -F "pom_file=@sample-customer-pom.xml" \
  | jq -r '.remediated_pom' > remediated-pom.xml

cat remediated-pom.xml
```

The output POM adds:
- A `<repository>` entry pointing to the Lightwell remediated repo on packages.redhat.com
- `<dependencyManagement>` overrides pinning vulnerable deps to `.rhlw-NNNNN` versions

### 4. Try your own POM

```bash
curl -s -X POST http://localhost:8000/api/lightwell/v0.1/resolve-pom/ \
  -F "pom_file=@/path/to/your/pom.xml" \
  | jq .
```

## Sample POM

`sample-customer-pom.xml` simulates a Spring Boot 2.6.6 application
("ACME Inventory Service") with 5 declared dependencies. The resolver
finds 63 transitive dependencies, 4 of which have Lightwell remediations
available:

| Dependency | How Found | Remediated Version | CVEs |
|---|---|---|---|
| spring-core 5.3.18 | transitive | 5.3.18.rhlw-00003 | 7 |
| org.json:json 20220320 | direct | 20220320.0.0.rhlw-00003 | 2 |
| json-path 2.8.0 | direct | 2.8.0.rhlw-00001 | 1 |
| woodstox-core 6.0.3 | direct | 6.0.3.rhlw-00001 | 1 |

Only packages with actual `.rhlw` builds on the Lightwell demo endpoint
are matched. The remaining 59 dependencies are reported as unmatched.

## Other API Endpoints

The server also exposes the full Lightwell API 0.1.0 spec:

```bash
# List repositories
curl -s http://localhost:8000/api/lightwell/v0.1/repositories/ | jq .

# List packages (filter by type)
curl -s "http://localhost:8000/api/lightwell/v0.1/packages/?type=maven" | jq .

# Look up a CVE
curl -s http://localhost:8000/api/lightwell/v0.1/cves/CVE-2024-38808/ | jq .

# List remediations
curl -s http://localhost:8000/api/lightwell/v0.1/remediations/ | jq .
```

## Architecture

```
sample-customer-pom.xml
        |
        v
  POST /resolve-pom/
        |
        v
  mvn dependency:tree    <-- full transitive resolution (subprocess)
        |
        v
  parse tree output      <-- pom_resolver.py
        |
        v
  match against catalog  <-- REMEDIATION_CATALOG (static for demo)
        |                    production: query Lightwell API /packages/
        v
  CVE lookup per match   <-- CVE_MAP (static for demo)
        |                    production: osv_cve_map + SecurityDataClient
        v
  generate remediated POM
        |
        v
  JSON response with summary, matches, full dep list, and patched POM
```

| File | Purpose |
|---|---|
| `app.py` | FastAPI routes for the Lightwell API + POM resolver endpoint |
| `pom_resolver.py` | Maven subprocess resolution, catalog matching, POM generation |
| `backends.py` | Pulp and Red Hat Security Data API clients |
| `schemas.py` | Pydantic response models |
| `mock_data.py` | Fallback data when Pulp credentials are unavailable |
| `sample-customer-pom.xml` | Demo customer POM for the resolver |
