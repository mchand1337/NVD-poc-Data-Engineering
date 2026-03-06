import streamlit as st
import duckdb
import pandas as pd
import altair as alt
from pathlib import Path

st.set_page_config(
    page_title="Vulnerability Dashboard",
    layout="wide",
    initial_sidebar_state="collapsed",
)

REDHAT_RED = "#EE0000"
REDHAT_DARK = "#151515"
BORDER = "#3b3b3b"
CARD_BG = "#1f1f1f"
TEXT = "#f5f5f5"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
SEVERITY_COLORS = {
    "CRITICAL": "#EE0000",  # red
    "HIGH": "#FF8C00",      # orange
    "MEDIUM": "#FFD600",    # yellow
    "LOW": "#4DA3FF",       # blue
    "NONE": "#2EAD5B",      # green
}

st.markdown(
    f"""
    <style>
        .stApp {{
            background-color: #0d1117;
            color: {TEXT};
        }}

        .block-container {{
            padding-top: 1.5rem;
            padding-bottom: 2rem;
        }}

        .dashboard-header {{
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 12px 18px;
            border: 1px solid {BORDER};
            border-radius: 14px;
            background: linear-gradient(90deg, rgba(238,0,0,0.18) 0%, rgba(31,31,31,1) 40%);
            margin-bottom: 1rem;
        }}

        .dashboard-title {{
            font-size: 2.1rem;
            font-weight: 700;
            color: white;
            margin: 0;
        }}

        .dashboard-subtitle {{
            margin: 0;
            color: #d0d0d0;
            font-size: 0.95rem;
        }}

        .section-card {{
            border: 1px solid {BORDER};
            border-radius: 14px;
            background-color: {CARD_BG};
            padding: 14px 16px 8px 16px;
            margin-bottom: 1rem;
        }}

        .kpi-card {{
            border: 1px solid {BORDER};
            border-left: 6px solid {REDHAT_RED};
            border-radius: 14px;
            background-color: {CARD_BG};
            padding: 16px;
        }}

        .kpi-label {{
            font-size: 0.9rem;
            color: #cfcfcf;
            margin-bottom: 0.35rem;
        }}

        .kpi-value {{
            font-size: 2rem;
            font-weight: 700;
            color: white;
        }}

        div[data-testid="stDataFrame"] {{
            border: 1px solid {BORDER};
            border-radius: 14px;
            overflow: hidden;
        }}
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_connection():
    return duckdb.connect("data/nvd.duckdb", read_only=True)


conn = get_connection()

# ---------- Header ----------
logo_path = Path("assets/redhat-logo.png")  # put your Red Hat logo file here

header_col1, header_col2 = st.columns([1, 12])
with header_col1:
    if logo_path.exists():
        st.image(str(logo_path), width=90)

with header_col2:
    st.markdown(
        """
        <div class="dashboard-header">
            <div>
                <p class="dashboard-title">Vulnerability Risk Dashboard</p>
                <p class="dashboard-subtitle">CVE severity, prioritization, and risk analytics</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ---------- KPI Query ----------
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
kpis = conn.execute(kpi_query).df().iloc[0]

# ---------- KPI Cards ----------
k1, k2, k3, k4 = st.columns(4)

with k1:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">Total Vulnerabilities</div>
            <div class="kpi-value">{int(kpis["total_vulnerabilities"]):,}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with k2:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">Critical</div>
            <div class="kpi-value">{int(kpis["critical_count"]):,}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with k3:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">High</div>
            <div class="kpi-value">{int(kpis["high_count"]):,}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with k4:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">Avg Base Score</div>
            <div class="kpi-value">{float(kpis["avg_base_score"]):.2f}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.write("")

# ---------- Severity Distribution ----------
severity_query = """
SELECT
    d.severity_name,
    d.severity_rank,
    COUNT(*) AS vuln_count
FROM gold_security.fact_vulnerability_scores f
JOIN gold_security.dim_severity d
  ON f.severity_key = d.severity_key
GROUP BY d.severity_name, d.severity_rank
"""
severity_df = conn.execute(severity_query).df()

# force desired order
severity_df["severity_name"] = pd.Categorical(
    severity_df["severity_name"],
    categories=SEVERITY_ORDER,
    ordered=True,
)
severity_df = (
    severity_df.sort_values("severity_name")
    .dropna(subset=["severity_name"])
    .reset_index(drop=True)
)

st.markdown('<div class="section-card">', unsafe_allow_html=True)
st.subheader("Severity Distribution")

severity_chart = (
    alt.Chart(severity_df)
    .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6)
    .encode(
        x=alt.X(
            "severity_name:N",
            sort=SEVERITY_ORDER,
            title="Severity",
            axis=alt.Axis(labelAngle=0),
        ),
        y=alt.Y("vuln_count:Q", title="Vulnerability Count"),
        color=alt.Color(
            "severity_name:N",
            scale=alt.Scale(
                domain=SEVERITY_ORDER,
                range=[SEVERITY_COLORS[s] for s in SEVERITY_ORDER],
            ),
            legend=None,
        ),
        tooltip=["severity_name", "vuln_count"],
    )
    .properties(height=360)
    .configure_view(stroke=None)
)

st.altair_chart(severity_chart, use_container_width=True)
st.markdown("</div>", unsafe_allow_html=True)

# ---------- Top Vulnerabilities ----------
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
ORDER BY f.base_score DESC, f.impact_score DESC, c.published_at DESC
LIMIT 20
"""
top_df = conn.execute(top_query).df()

# optional date formatting
if "published_at" in top_df.columns:
    top_df["published_at"] = pd.to_datetime(top_df["published_at"], errors="coerce")

def color_severity(val: str):
    color = SEVERITY_COLORS.get(val, "#999999")
    return f"background-color: {color}; color: black; font-weight: 700;"

styled_top_df = (
    top_df.style
    .format(
        {
            "published_at": lambda x: x.strftime("%Y-%m-%d %H:%M:%S") if pd.notnull(x) else "",
            "base_score": "{:.1f}",
            "exploitability_score": "{:.1f}",
            "impact_score": "{:.1f}",
        }
    )
    .map(color_severity, subset=["severity_name"])
)

st.markdown('<div class="section-card">', unsafe_allow_html=True)
st.subheader("Top 20 Vulnerabilities")
st.dataframe(
    styled_top_df,
    use_container_width=True,
    hide_index=True,
    column_config={
        "cve_id": st.column_config.TextColumn("CVE ID"),
        "published_at": st.column_config.DatetimeColumn("Published At", format="YYYY-MM-DD HH:mm:ss"),
        "base_score": st.column_config.NumberColumn("Base Score", format="%.1f"),
        "exploitability_score": st.column_config.NumberColumn("Exploitability", format="%.1f"),
        "impact_score": st.column_config.NumberColumn("Impact", format="%.1f"),
        "severity_name": st.column_config.TextColumn("Severity"),
    },
)
st.markdown("</div>", unsafe_allow_html=True)