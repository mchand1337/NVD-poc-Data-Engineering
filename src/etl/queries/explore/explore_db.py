import duckdb

con = duckdb.connect("data/nvd.duckdb")

print("\n=== TABLES ===")
print(con.execute("SHOW TABLES").fetchdf())

print("\n=== CVE COUNT ===")
print(con.execute("SELECT COUNT(*) FROM bronze_nvd.cve_raw").fetchdf())

print("\n=== Severity Distribution ===")
print(con.execute("""
    SELECT base_severity, COUNT(*) as count
    FROM bronze_nvd.cvss_v3_raw
    GROUP BY base_severity
    ORDER BY count DESC
""").fetchdf())

print("\n=== Most Recent CVEs ===")
print(con.execute("""
    SELECT cve_id, last_modified
    FROM bronze_nvd.cve_raw
    ORDER BY last_modified DESC
    LIMIT 10
""").fetchdf())

con.close()