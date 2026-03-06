DELETE FROM silver_nvd.cvss_v3
WHERE CAST(silver_load_timestamp as date) BETWEEN (CURRENT_DATE() - INTERVAL '7' DAY) AND CURRENT_DATE();

INSERT INTO silver_nvd.cvss_v3
(
cve_id
,version
,vector
,base_score
,base_severity
,exploitability_score
,impact_score
,silver_load_timestamp
)
SELECT
cve_id
,version
,vector
,base_score
,base_severity
,exploitability_score
,impact_score
,CURRENT_TIMESTAMP as silver_load_timestamp
FROM bronze_nvd.cvss_v3_raw
WHERE CAST(
        TRIM(TRAILING '.json' FROM (RIGHT(source_file, 15)))
     AS DATE
     ) in (
        SELECT MAX(
            CAST(
                TRIM(TRAILING '.json' FROM (RIGHT(source_file, 15)))
            AS DATE)
        )
    FROM bronze_nvd.cvss_v3_raw
);
