CREATE TABLE "gold_security"."dim_cvss_characteristics" (
    "cvss_characteristic_key" BIGINT,
    "cvss_version" VARCHAR,
    "cvss_vector" VARCHAR,
    "attack_vector" VARCHAR,
    "attack_complexity" VARCHAR,
    "privileges_required" VARCHAR,
    "user_interaction" VARCHAR,
    "scope" VARCHAR,
    "base_severity" VARCHAR,
    "is_critical" BOOLEAN,
    "confidentiality_impact" VARCHAR,
    "integrity_impact" VARCHAR,
    "availability_impact" VARCHAR,
    "is_critical_1" BOOLEAN,
    "gold_load_timestamp" TIMESTAMP WITH TIME ZONE
);