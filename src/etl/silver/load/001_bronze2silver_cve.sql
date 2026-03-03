INSERT INTO silver_nvd.cve
(
cve_id
,published
,last_modified
,description
,CURRENT_TIMESTAMP() as silver_load_timestamp
)
SELECT
cve_id
,published,
,last_modified
,description
silver_load_timestamp
FROM bronze_nvd.cve_raw
WHERE CAST(ingested_at as date) IN
    (
        SELECT MAX(CAST(ingested_at as date)) 
        FROM bronze_nvd.cve_raw
    )
;