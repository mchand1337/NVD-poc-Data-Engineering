CREATE TABLE "bronze_nvd"."cve_raw" (
    "cve_id" VARCHAR NOT NULL,
    "published" TIMESTAMP,
    "last_modified" TIMESTAMP,
    "description" VARCHAR,
    "source_file" VARCHAR,
    "ingested_at" TIMESTAMP
);