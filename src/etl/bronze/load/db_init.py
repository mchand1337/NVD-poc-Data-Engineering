import duckdb
from pathlib import Path

DB_PATH = Path("data") / "nvd.duckdb"

def main():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    con = duckdb.connect(str(DB_PATH))

    con.execute("""
    CREATE TABLE IF NOT EXISTS cve (
        cve_id TEXT PRIMARY KEY,
        published TIMESTAMP,
        last_modified TIMESTAMP,
        description TEXT
    );
    """)

    # Keep it simple: store v3.1 if present (you can expand later)
    con.execute("""
    CREATE TABLE IF NOT EXISTS cvss_v31 (
        cve_id TEXT,
        base_score DOUBLE,
        base_severity TEXT,
        vector_string TEXT,
        PRIMARY KEY (cve_id),
        FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
    );
    """)

    con.close()
    print(f"Initialized DB at {DB_PATH.resolve()}")

if __name__ == "__main__":
    main()