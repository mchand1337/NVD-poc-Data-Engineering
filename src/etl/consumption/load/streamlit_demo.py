import streamlit as st
import duckdb
import pandas as pd

st.set_page_config(page_title="Vulnerability Dashboard", layout="wide")

@st.cache_resource
def get_connection():
    return duckdb.connect("data/nvd.duckdb")

conn = get_connection()

st.title("Vulnerability Risk Dashboard")

kpi_query = """
SELECT
    COUNT(*) AS total_vulnerabilities,
    SUM(CASE WHEN d.severity_name = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
    SUM(CASE WHEN d.severity_name = 'HIGH' THEN 1 ELSE 0 END) AS high_count,
    ROUND(AVG(f.base_score), 2) AS avg_base_score
FROM gold_security.fact_vulnerability_scores f
JOIN gold_security.dim_severity d
  ON f.severity_key = d.severity_key
"""

kpis = conn.execute(kpi_query).df()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Vulnerabilities", int(kpis.loc[0, "total_vulnerabilities"]))
col2.metric("Critical", int(kpis.loc[0, "critical_count"]))
col3.metric("High", int(kpis.loc[0, "high_count"]))
col4.metric("Avg Base Score", float(kpis.loc[0, "avg_base_score"]))

severity_query = """
SELECT
    d.severity_name,
    COUNT(*) AS vuln_count
FROM gold_security.fact_vulnerability_scores f
JOIN gold_security.dim_severity d
  ON f.severity_key = d.severity_key
GROUP BY d.severity_name, d.severity_rank
ORDER BY d.severity_rank DESC
"""

severity_df = conn.execute(severity_query).df()
st.subheader("Severity Distribution")
st.bar_chart(severity_df.set_index("severity_name"))

top_query = """
SELECT
    c.cve_id,
    c.published_at,
    f.base_score,
    f.exploitability_score,
    f.impact_score,
    s.severity_name
FROM gold_security.fact_vulnerability_scores f
JOIN gold_security.dim_cve c
  ON f.dim_cve_key = c.dim_cve_key
JOIN gold_security.dim_severity s
  ON f.severity_key = s.severity_key
ORDER BY f.base_score DESC, f.impact_score DESC
LIMIT 20
"""

top_df = conn.execute(top_query).df()
st.subheader("Top 20 Vulnerabilities")
st.dataframe(top_df, use_container_width=True)