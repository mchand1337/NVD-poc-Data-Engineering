CREATE TABLE "bronze_nvd"."cvss_v3_raw" (
    "cve_id" VARCHAR,
    "version" VARCHAR,
    "vector" VARCHAR,
    "base_score" DOUBLE,
    "base_severity" VARCHAR,
    "exploitability_score" DOUBLE,
    "impact_score" DOUBLE,
    "source_file" VARCHAR
);