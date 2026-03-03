CREATE TABLE "silver_nvd"."cve" (
    "cve_id" VARCHAR NOT NULL,
    "published" TIMESTAMP,
    "last_modified" TIMESTAMP,
    "description" VARCHAR,
    "silver_load_timestamp" TIMESTAMP
);