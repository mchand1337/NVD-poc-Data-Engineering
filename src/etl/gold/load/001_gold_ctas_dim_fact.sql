CREATE OR REPLACE TABLE gold_security.dim_cve AS
SELECT
  ROW_NUMBER() OVER (ORDER BY cve_id) AS dim_cve_key,
  cve_id,
  published_at,
  last_modified_at,
  description,
  CURRENT_TIMESTAMP as gold_load_timestamp
FROM silver_nvd.vulnerability_summary;

CREATE OR REPLACE TABLE gold_security.dim_cvss_characteristics AS
SELECT
  ROW_NUMBER() OVER (ORDER BY COALESCE(cvss_vector, ''), COALESCE(cvss_version, '')) AS cvss_characteristic_key,
  cvss_version,
  cvss_vector,
  attack_vector,
  attack_complexity,
  privileges_required,
  user_interaction,
  scope,
  base_severity,
  is_critical,
  confidentiality_impact,
  integrity_impact,
  availability_impact,
  is_critical,
  gold_load_timestamp
FROM (
  SELECT DISTINCT
    cvss_version,
    cvss_vector,
    attack_vector,
    attack_complexity,
    privileges_required,
    user_interaction,
    scope,
    base_severity,
    is_critical,
    confidentiality_impact,
    integrity_impact,
    availability_impact,
    CURRENT_TIMESTAMP as gold_load_timestamp
  FROM silver_nvd.vulnerability_summary
);

-- Fact
CREATE OR REPLACE TABLE gold_security.fact_vulnerability_scores AS
SELECT
    ROW_NUMBER() OVER (ORDER BY s.cve_id) AS fact_vuln_score_key,
    d_cve.dim_cve_key,
    d_cvss.cvss_characteristic_key,
    d_sev.severity_key,
    s.base_score,
    s.exploitability_score,
    s.impact_score,
    CURRENT_TIMESTAMP as gold_load_timestamp
FROM silver_nvd.vulnerability_summary s
LEFT JOIN gold_security.dim_cve d_cve
    ON s.cve_id = d_cve.cve_id
LEFT JOIN gold_security.dim_severity d_sev
    ON s.base_severity = d_sev.severity_name
LEFT JOIN gold_security.dim_cvss_characteristics d_cvss
    ON s.cvss_version = d_cvss.cvss_version
    AND s.cvss_vector = d_cvss.cvss_vector;