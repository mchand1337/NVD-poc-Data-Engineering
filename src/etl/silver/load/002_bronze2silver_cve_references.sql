DELETE FROM silver_nvd.cve_references
WHERE CAST(silver_load_timestamp as date) BETWEEN (CURRENT_DATE() - INTERVAL '7' DAY) AND CURRENT_DATE();

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
        TRIM(TRAILING '.json' FROM (RIGHT(source_file, 15)))
     AS DATE
     ) in (
        SELECT MAX(
            CAST(
                TRIM(TRAILING '.json' FROM (RIGHT(source_file, 15)))
            AS DATE)
        )
    FROM bronze_nvd.cve_references_raw
);


--debug statement on date text in bronze
-- SELECT CAST(TRIM(TRAILING '.json' FROM (RIGHT(source_file, 15)))AS DATE)
-- FROM bronze_nvd.cve_references_raw
-- ;

--debug statement on increment logic for idemoptency
-- select
-- case 
--     when cast(silver_load_timestamp as date) <= CURRENT_DATE() and cast(silver_load_timestamp as date) >= (CURRENT_DATE() - INTERVAL '7' DAY) then TRUE
--     else FALSE
--     END as check_recent_load
-- from silver_nvd.cve_references;


