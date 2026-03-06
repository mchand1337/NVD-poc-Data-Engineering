## NVD PoC – Data Engineering

### What this repo demonstrates
- End-to-end ingestion of NVD CVE data (bronze) → incremental normalization (silver) → curated security mart (gold/consumption ready) in DuckDB.
- Idempotent batch loads with schema separation and batch-date guards.
- Exploratory queries that surface actionable signals for a product security audience (e.g., exploitable CVEs, severity mix, recency).

### Quickstart (local, ~5 minutes)
1) Install deps (Python 3.11+):
```bash
pip install -r requirements.txt
```
2) Fetch recent CVEs (defaults to last 7 days):
```bash
python src/etl/bronze/load/fetch_one_cve.py
```
3) Normalize into DuckDB bronze/silver schemas (rebuilds schemas for a clean demo run):
```bash
python src/etl/bronze/load/normalize_to_duckdb.py
```
4) Run exploratory queries (edit as needed):
```bash
python -m duckdb data/nvd.duckdb -c "\i src/etl/queries/explore/explore_query.sql"
```

### Data flow
- **Bronze**: Raw JSON from NVD stored as `bronze_nvd.cve_raw`, `cvss_v3_raw`, `cve_references_raw` with lineage columns (`source_file`, `ingested_at`).
- **Silver**: Recent batch-only upserts into `silver_nvd.cve`, `cve_references`, `cvss_v3` using batch-date filters for idempotency.
- **(Future) Gold/Security mart**: Space reserved for curated, business-facing aggregates (e.g., exploit-labeled backlog, severity SLA tracking). Highlight how you'd materialize views into `security_mart` / `gold_security`.

### Story hooks for product security
- Prioritize: Exploitable-tagged CVEs and high-severity (base_score >= 7) surfaced quickly.
- Recency: Show most recently modified CVEs to focus patching.
- Coverage: Count by severity and by tag to spot hotspots (exploit vs. patch references).
- Idempotency & traceability: Batch-date filters and `source_file` lineage keep reruns safe.

### Sample queries to demo (DuckDB)
- Severity distribution and recency:
```sql
SELECT base_severity, COUNT(*) AS count
FROM bronze_nvd.cvss_v3_raw
GROUP BY base_severity
ORDER BY count DESC;

SELECT cve_id, last_modified
FROM bronze_nvd.cve_raw
ORDER BY last_modified DESC
LIMIT 10;
```
- Exploit or patch-related CVEs (joined view):
```sql
SELECT
  c.cve_id,
  c.published,
  c.last_modified,
  c.description,
  r.tags,
  v.vector,
  v.base_score,
  v.base_severity,
  v.exploitability_score,
  v.impact_score
FROM bronze_nvd.cve_raw AS c
JOIN bronze_nvd.cvss_v3_raw AS v ON c.cve_id = v.cve_id
JOIN bronze_nvd.cve_references_raw AS r ON c.cve_id = r.cve_id
WHERE LOWER(r.tags) LIKE '%exploit%' OR LOWER(r.tags) LIKE '%patch%'
ORDER BY v.base_score DESC
LIMIT 50;
```

### What to improve
- Orchestration: add a simple Dagster/Airflow or GitHub Actions schedule for daily pulls.
- Quality: add schema tests (e.g., Great Expectations/dbt) for non-null severities, valid CVE IDs, and monotonic `last_modified` per CVE.
- Serving: expose curated metrics via FastAPI (uvicorn) or ship Parquet extracts to S3/minio.
- Enrichment: map CPEs to product ownership, add EPSS/KEV feeds, and compute risk scores.
- Observability: add row counts and freshness checks per layer, log batch IDs, and publish a run report.

### Repo map
- `src/etl/bronze/load/`: fetch raw JSON and normalize into DuckDB schemas.
- `src/etl/bronze/ddl/`: base tables for raw CVE, CVSS, references.
- `src/etl/silver/ddl/` and `src/etl/silver/load/`: incremental batch loads into cleaner silver tables.
- `src/etl/queries/explore/`: demo queries and quick stats.
- `src/etl/gold/` and `src/etl/consumption/`: placeholders for curated marts/views.

### Demo cadence
1) Show folder layout and layer purpose (bronze→silver→gold/consumption).
2) Run fetch → normalize → queries, narrating lineage and idempotency.
3) Highlight exploit/patch-focused join and severity distribution.
4) Close with roadmap: orchestration, quality checks, enrichment, serving.
