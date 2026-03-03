INSERT INTO silver_nvd.cve_references
(
cve_id
,url
,tags
,silver_load_timestamp
)
SELECT
cve_id
,url
,tags
,CURRENT_TIMESTAMP as silver_load_timestamp
FROM bronze_nvd.cve_references_raw
WHERE CAST(
        regexp_extract(source_file, '(\\d{4}-\\d{2}-\\d{2})\\.json$', 1)
     AS DATE
     ) = (
        SELECT MAX(
            CAST(
                regexp_extract(source_file, '(\\d{4}-\\d{2}-\\d{2})\\.json$', 1)
            AS DATE)
        )
    FROM bronze_nvd.cve_references_raw
);