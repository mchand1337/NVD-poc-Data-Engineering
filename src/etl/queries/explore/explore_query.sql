SELECT *
FROM bronze_nvd.cve_raw
where cve_id = 'CVE-2026-2889'
LIMIT 20;
-- cve_id
-- source_file
-- description


SELECT * 
FROM bronze_nvd.cvss_v3_raw
where cve_id = 'CVE-2026-2889'
LIMIT 20;
-- cve_id
-- version
-- vector
-- base_score
-- base_severity
-- exploitability_score
-- impact_score
-- source_file


SELECT * 
FROM bronze_nvd.cve_references_raw

-- where cve_id = 'CVE-2026-2889'
order by cve_id asc
LIMIT 1000;

SELECT tags, COUNT(*) as record_count
FROM bronze_nvd.cve_references_raw
GROUP BY tags
ORDER BY tags;

SELECT tags, COUNT(*) as record_count
FROM bronze_nvd.cve_references_raw
where lower(tags) like '%exploit%'
or lower(tags) = 'patch'
GROUP BY  tags;

select DISTINCT(version)
from bronze_nvd.cvss_v3_raw;


SELECT
cve_raw.cve_id
,cve_raw.published
,cve_raw.last_modified
,cve_raw.description
,cve_ref.tags
,cvss_v3.vector
,cvss_v3.version
,cvss_v3.base_score
,cvss_v3.base_severity
,cvss_v3.exploitability_score
,cvss_v3.impact_score
FROM bronze_nvd.cve_raw cve_raw
inner JOIN bronze_nvd.cvss_v3_raw cvss_v3
    on cve_raw.cve_id = cvss_v3.cve_id
inner JOIN bronze_nvd.cve_references_raw cve_ref
    on cve_raw.cve_id = cve_ref.cve_id
WHERE (cve_ref.tags like '%Exploit%' or cve_ref.tags like '%Patch%');