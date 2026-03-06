DELETE FROM silver_nvd.cve
WHERE CAST(silver_load_timestamp as date) BETWEEN (CURRENT_DATE() - INTERVAL '7' DAY) AND CURRENT_DATE();

INSERT INTO silver_nvd.cve
(
cve_id
,published
,last_modified
,description
,silver_load_timestamp
)
SELECT
cve_id
,published
,last_modified
,description
,CURRENT_TIMESTAMP as silver_load_timestamp
FROM bronze_nvd.cve_raw
WHERE CAST(ingested_at as date) IN
    (
        SELECT MAX(CAST(ingested_at as date)) 
        FROM bronze_nvd.cve_raw
    )
;