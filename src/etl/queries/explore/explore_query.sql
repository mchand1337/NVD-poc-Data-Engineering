-- === Fast spotlight: exploitable or patch-related, ordered by severity ===
SELECT
  c.cve_id,
  c.published,
  c.last_modified,
  c.description,
  v.vector,
  v.version,
  v.base_severity,
  v.base_score,
  v.exploitability_score,
  v.impact_score
FROM bronze_nvd.cve_raw AS c
inner JOIN bronze_nvd.cvss_v3_raw AS v ON c.cve_id = v.cve_id
ORDER BY v.base_score DESC NULLS LAST, c.last_modified DESC
LIMIT 50;

-- === Severity distribution (how many critical/high/medium/low) ===
SELECT base_severity, COUNT(*) AS count
FROM bronze_nvd.cvss_v3_raw
GROUP BY base_severity
ORDER BY count DESC;

-- === Recency: most recently modified CVEs ===
SELECT cve_id, last_modified
FROM bronze_nvd.cve_raw
ORDER BY last_modified DESC
LIMIT 10;

-- === Tag coverage: which reference tags appear most ===
SELECT tags, COUNT(*) AS record_count
FROM bronze_nvd.cve_references_raw
GROUP BY tags
ORDER BY record_count DESC
LIMIT 50;

-- === Version coverage (CVSS 3.1 vs 3.0 etc.) ===
SELECT DISTINCT version
FROM bronze_nvd.cvss_v3_raw
ORDER BY version;

-- === (Optional) inspect one CVE end-to-end ===
-- Replace the CVE ID below as needed
-- SELECT * FROM bronze_nvd.cve_raw WHERE cve_id = 'CVE-2026-2889';
-- SELECT * FROM bronze_nvd.cvss_v3_raw WHERE cve_id = 'CVE-2026-2889';
-- SELECT * FROM bronze_nvd.cve_references_raw WHERE cve_id = 'CVE-2026-2889';
