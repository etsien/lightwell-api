# ACME Inventory Service

A small Spring Boot application representing a typical customer workload.
It manages warehouse inventory through a REST API and uses several open-source
libraries that have known CVEs -- making it a realistic target for the Lightwell
POM remediation demo.

| Property | Value |
|----------|-------|
| Spring Boot | 2.6.6 (spring-core 5.3.18) |
| Java | 17 |
| Build tool | Maven |
| GroupId | `com.example` |
| Artifact | `acme-inventory-service-3.2.1.jar` |

## Dependencies and why they matter

| Dependency | Version | Used for | Lightwell remediation |
|------------|---------|----------|-----------------------|
| `spring-boot-starter-web` | 2.6.6 | REST API framework | spring-core 5.3.18.rhlw-00010 |
| `org.json:json` | 20220320 | Bulk JSON import/export | 20220320.0.0.rhlw-00003 |
| `com.jayway.jsonpath:json-path` | 2.8.0 | JSONPath inventory queries | 2.8.0.rhlw-00001 |
| `com.fasterxml.woodstox:woodstox-core` | 6.0.3 | XML legacy feed integration | 6.0.3.rhlw-00001 |

## Quick start

```bash
mvn clean package
mvn spring-boot:run
```

## API endpoints

### CRUD

```bash
# List all items
curl -s http://localhost:8080/api/inventory | jq

# Get one item
curl -s http://localhost:8080/api/inventory/{id} | jq

# Create
curl -s -X POST http://localhost:8080/api/inventory \
  -H 'Content-Type: application/json' \
  -d '{"sku":"NEW-001","name":"Torque Wrench","category":"tools","quantity":50,"price":89.99,"warehouse":"east"}' | jq

# Delete
curl -s -X DELETE http://localhost:8080/api/inventory/{id}
```

### Bulk JSON (uses org.json)

```bash
# Export
curl -s http://localhost:8080/api/inventory/export/json | jq

# Import
curl -s -X POST http://localhost:8080/api/inventory/import/json \
  -H 'Content-Type: application/json' \
  -d @inventory-export.json
```

### JSONPath query (uses json-path)

```bash
# All items in the "safety" category
curl -s 'http://localhost:8080/api/inventory/query?path=$.items[?(@.category=="safety")]' | jq

# Names of items with quantity > 1000
curl -s 'http://localhost:8080/api/inventory/query?path=$.items[?(@.quantity>1000)].name' | jq

# Total item count
curl -s 'http://localhost:8080/api/inventory/query?path=$.itemCount'
```

### XML legacy feed (uses woodstox-core)

```bash
# Export as XML
curl -s http://localhost:8080/api/inventory/export/xml

# Import from XML
curl -s -X POST http://localhost:8080/api/inventory/import/xml \
  -H 'Content-Type: application/xml' \
  -d '<inventory><item><sku>XML-001</sku><name>Imported Part</name><category>parts</category><quantity>100</quantity><price>5.50</price><warehouse>east</warehouse></item></inventory>'
```

## POM remediation demo

This application's `pom.xml` is the input to the Lightwell POM resolver demo
(`lightwell-api-demo/`). The resolver scans the dependency tree, identifies
components with known vulnerabilities, and produces a remediated POM that pins
those dependencies to Lightwell's patched `.rhlw-*` builds.

```bash
# Run the resolver against this app's POM
curl -s -X POST http://localhost:8000/resolve-pom/ \
  -F "pom_file=@pom.xml" | jq
```
