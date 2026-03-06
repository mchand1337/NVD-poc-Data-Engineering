CREATE TABLE "gold_security"."dim_severity" (
    "severity_key" INTEGER,
    "severity_name" VARCHAR,
    "severity_rank" INTEGER,
    "min_score" DECIMAL(3,1),
    "max_score" DECIMAL(3,1)
);