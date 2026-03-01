import json
from pathlib import Path
from datetime import datetime

import duckdb
import pandas as pd
import os

RAW_DIR = (Path(__file__).resolve().parents[1] / "data" / "raw").resolve()
DB_PATH = (Path(__file__).resolve().parents[1] / "data" / "nvd.duckdb").resolve()

print(f"[debug] RAW_DIR = {RAW_DIR}")
print(f"[debug] RAW_DIR exists? {RAW_DIR.exists()}")

raw_files = sorted(RAW_DIR.glob("*.json"))
print(f"[debug] Found {len(raw_files)} json files")
for p in raw_files[:5]:
    print(f"[debug] - {p.name}")

def pick_english_description(descs):
    for d in descs or []:
        if d.get("lang") == "en":
            return d.get("value")
    return (descs or [{}])[0].get("value")

def parse_cvss(metrics: dict):
    """Return best-effort CVSS v3.1 or v3.0 row or None."""
    if not metrics:
        return None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key)
        if arr and isinstance(arr, list):
            m = arr[0]
            cvss = (m.get("cvssData") or {})
            return {
                "version": cvss.get("version"),
                "vector": cvss.get("vectorString"),
                "base_score": cvss.get("baseScore"),
                "base_severity": cvss.get("baseSeverity"),
                "exploitability_score": m.get("exploitabilityScore"),
                "impact_score": m.get("impactScore"),
                "attackVector": cvss.get("attackVector"),
                "attackComplexity": cvss.get("attackComplexity"),
                "privilegesRequired": cvss.get("privilegesRequired"),
                "userInteraction": cvss.get("userInteraction"),
                "scope": cvss.get("scope"),
                "confidentialityImpact": cvss.get("confidentialityImpact"),
                "integrityImpact": cvss.get("integrityImpact"),
                "availabilityImpact": cvss.get("availabilityImpact"),
                "baseScore": m.get("baseScore"),
                "baseSeverity": m.get("baseSeverity"),
            }
    return None
    
def main():
        # ******************************************* #
        # HARD RESET: Delete DB if it exists to ensure idempotent run for this demo
        # ******************************************* #

        if DB_PATH.exists():
            print(f"[debug] Removing existing DB at {DB_PATH.resolve()} for clean demo run")
            con = duckdb.connect(str(DB_PATH))

            con.execute("DROP SCHEMA IF EXISTS bronze_nvd CASCADE;")
            con.execute("DROP SCHEMA IF EXISTS silver_nvd CASCADE;")
            con.execute("DROP SCHEMA IF EXISTS gold_nvd CASCADE;")
            con.execute("DROP SCHEMA IF EXISTS security_metrics_mart CASCADE;")

            con.close()
        
        print("[reset] Deleting existing DB at {DB_PATH}")

        # Pick latest raw file by modified time
        raw_files = sorted(RAW_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not raw_files:
            raise SystemExit(f"No raw files found in {RAW_DIR.resolve()}")

        raw_path = raw_files[0]
        payload = json.loads(raw_path.read_text(encoding="utf-8"))

        vulns = payload.get("vulnerabilities", [])
        cve_rows = []
        cvss_rows = []
        ref_rows = []

        for item in vulns:
            cve = (item.get("cve") or {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            published = cve.get("published")
            last_modified = cve.get("lastModified")

            desc = pick_english_description(cve.get("descriptions") or [])

            cve_rows.append({
                "cve_id": cve_id,
                "published": published,
                "last_modified": last_modified,
                "description": desc,
                "source_file": raw_path.name,
                "ingested_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            })

            cvss = parse_cvss(cve.get("metrics") or {})
            if cvss:
                cvss_rows.append({
                    "cve_id": cve_id,
                    **cvss,
                    "source_file": raw_path.name
                })


            refs = (cve.get("references") or [])
            for r in refs:
                ref_rows.append({
                    "cve_id": cve_id,
                    "url": r.get("url"),
                    "tags": ",".join(r.get("tags") or []),
                    "source_file": raw_path.name,
                })
            
        cve_df = pd.DataFrame(cve_rows)
        cvss_df = pd.DataFrame(cvss_rows)
        ref_df = pd.DataFrame(ref_rows)

        DB_PATH.parent.mkdir(parents=True, exist_ok=True)

        con = duckdb.connect(str(DB_PATH))

        con.execute("CREATE SCHEMA IF NOT EXISTS bronze_nvd;")
        con.execute("CREATE SCHEMA IF NOT EXISTS silver_nvd;")
        con.execute("CREATE SCHEMA IF NOT EXISTS gold_security;")
        con.execute("CREATE SCHEMA IF NOT EXISTS security_mart;")

        con.execute("""
        CREATE TABLE IF NOT EXISTS bronze_nvd.cve_raw (
            cve_id TEXT PRIMARY KEY,
            published TIMESTAMP,
            last_modified TIMESTAMP,
            description TEXT,
            source_file TEXT,
            ingested_at TIMESTAMP
        );
        """)

        con.execute("""
        CREATE TABLE IF NOT EXISTS bronze_nvd.cvss_v3_raw (
            cve_id TEXT,
            version TEXT,
            vector TEXT,
            base_score DOUBLE,
            base_severity TEXT,
            exploitability_score DOUBLE,
            impact_score DOUBLE,
            source_file TEXT
        );
        """)

        con.execute("""
        CREATE TABLE IF NOT EXISTS bronze_nvd.cve_references_raw (
            cve_id TEXT,
            url TEXT,
            tags TEXT,
            source_file TEXT
        );
        """)

        # Upsert-ish: insert new CVEs, refresh child tables for this batch
        con.register("cve_df", cve_df)
        con.execute("""
            INSERT INTO bronze_nvd.cve_raw (
                    cve_id, 
                    published, 
                    last_modified, 
                    description, 
                    source_file, 
                    ingested_at
                    )
            SELECT 
                cve_id, 
                CAST(published AS TIMESTAMP) AS published,
                CAST(last_modified AS TIMESTAMP) AS last_modified,
                description, 
                source_file, 
                CAST(ingested_at AS TIMESTAMP) AS ingested_at
            FROM cve_df
            ON CONFLICT (cve_id) DO UPDATE SET
                published=excluded.published,
                last_modified=excluded.last_modified,
                description=excluded.description,
                source_file=excluded.source_file,
                ingested_at=excluded.ingested_at;
        """)

        # Replace child rows for this source_file to keep idempotent runs
        con.execute("""
                    DELETE FROM bronze_nvd.cvss_v3_raw 
                    WHERE source_file = ?
                    """, 
                    [raw_path.name]
                    )
        con.execute("""
                    DELETE FROM bronze_nvd.cve_references_raw 
                    WHERE source_file = ?
                    """, 
                    [raw_path.name])

        if not cvss_df.empty:
            con.register("cvss_df", cvss_df)
            con.execute("""
                INSERT INTO bronze_nvd.cvss_v3_raw (
                    cve_id,
                    version, 
                    vector, 
                    base_score,
                    base_severity,
                    exploitability_score, 
                    impact_score, 
                    source_file
                )
                SELECT
                    cve_id, 
                    version, 
                    vector,
                    base_score, 
                    base_severity,
                    exploitability_score, 
                    impact_score,
                    source_file
                FROM cvss_df   
            """)

        if not ref_df.empty:
    # Ensure stable column set/order
            ref_df = ref_df.reindex(columns=["cve_id", "url", "tags", "source_file"])
            con.register("ref_df", ref_df)

            con.execute("""
                INSERT INTO bronze_nvd.cve_references_raw (
                        cve_id, 
                        url, 
                        tags, 
                        source_file
                        )
                SELECT 
                        cve_id, 
                        url, 
                        tags, 
                        source_file
                FROM ref_df
            """)

        # quick sanity stats
        total_cves = con.execute("SELECT COUNT(*) FROM bronze_nvd.cve_raw").fetchone()[0]
        batch_cves = len(cve_df)
        print(f"Loaded batch file: {raw_path.name}")
        print(f"Batch CVEs: {batch_cves} | Total CVEs in DB: {total_cves}")
        print(f"DB saved at: {DB_PATH.resolve()}")

        con.close()

if __name__ == "__main__":
    main()