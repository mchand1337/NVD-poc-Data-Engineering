CREATE TABLE "silver_nvd"."cvss_v3" (
    "cve_id" VARCHAR,
    "version" VARCHAR,
    "vector" VARCHAR,
    "base_score" DOUBLE,
    "base_severity" VARCHAR,
    "exploitability_score" DOUBLE,
    "impact_score" DOUBLE,
    "silver_load_timestamp" TIMESTAMP
);