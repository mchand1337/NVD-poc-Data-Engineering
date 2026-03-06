## NVD PoC – Data Engineering

### What this repo demonstrates
- End-to-end ingestion of NVD CVE data (bronze) → incremental normalization (silver) → curated security mart (gold/consumption ready) in DuckDB.
- Idempotent batch loads with schema separation and batch-date guards.
- Exploratory queries that surface actionable signals for a product security audience (e.g., exploitable CVEs, severity mix, recency).

### Quick Facts
| Metric Category        | Abbreviation | Grade Vector         | Meaning                      | Possible Grades                                    |
| ---------------------- | ------------ | -------------------- | ---------------------------- | -------------------------------------------------- |
| Attack Vector          | AV           | L                    | Local access required        | N (Network), A (Adjacent), L (Local), P (Physical) |
| Attack Complexity      | AC           | L                    | Low complexity to exploit    | L (Low), H (High)                                  |
| Privileges Required    | PR           | L                    | Low privileges needed        | N (None), L (Low), H (High)                        |
| User Interaction       | UI           | N                    | No user interaction required | N (None), R (Required)                             |
| Scope                  | S            | U                    | Scope unchanged              | U (Unchanged), C (Changed)                         |
| Confidentiality Impact | C            | N                    | No confidentiality impact    | N (None), L (Low), H (High)                        |
| Integrity Impact       | I            | N                    | No integrity impact          | N (None), L (Low), H (High)                        |
| Availability Impact    | A            | L                    | Low availability impact      | N (None), L (Low), H (High)                        |


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
    v.version,
    v.vector,
    v.base_severity,
    v.base_score,
    v.exploitability_score,
    v.impact_score,
    regexp_extract(v.vector, 'AV:([A-Z])', 1) AS attack_vector,
    regexp_extract(v.vector, 'AC:([A-Z])', 1) AS attack_complexity,
    regexp_extract(v.vector, 'PR:([A-Z])', 1) AS privileges_required,
    regexp_extract(v.vector, 'UI:([A-Z])', 1) AS user_interaction,
    regexp_extract(v.vector, 'S:([A-Z])', 1) AS scope,
    regexp_extract(v.vector, 'C:([A-Z])', 1) AS confidentiality_impact,
    regexp_extract(v.vector, 'I:([A-Z])', 1) AS integrity_impact,
    regexp_extract(v.vector, 'A:([A-Z])', 1) AS availability_impact,
    CASE v.base_severity
        WHEN 'CRITICAL' THEN 4
        WHEN 'HIGH' THEN 3
        WHEN 'MEDIUM' THEN 2
        WHEN 'LOW' THEN 1
        ELSE 0
    END,
    v.base_severity = 'CRITICAL',
    CURRENT_TIMESTAMP
FROM bronze_nvd.cve_raw c
LEFT JOIN bronze_nvd.cvss_v3_raw v
ON c.cve_id = v.cve_id;
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
