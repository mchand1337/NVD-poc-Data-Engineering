CREATE TABLE "gold_security"."dim_cve" (
    "dim_cve_key" BIGINT,
    "cve_id" VARCHAR,
    "published_at" TIMESTAMP,
    "last_modified_at" TIMESTAMP,
    "description" VARCHAR,
    "gold_load_timestamp" TIMESTAMP WITH TIME ZONE
);