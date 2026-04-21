import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv

from scanner_core import analyze_project

load_dotenv()

st.set_page_config(page_title="SBOM Risk Dashboard", layout="wide")
st.title("SBOM-Based Cyber Risk Assessment Dashboard")
st.caption("Research prototype: SBOM generation, dependency extraction, live CVE lookup, and risk ranking")

target_path = st.text_input("Target project path", value=".")
max_components = st.slider("Max components to enrich with live CVE lookups", 5, 100, 30)

if st.button("Run Scan"):
    with st.spinner("Generating SBOM and querying vulnerability sources..."):
        data = analyze_project(target_path=target_path, max_components=max_components)

    results_df = pd.DataFrame(data["results"])
    edges_df = pd.DataFrame(data["edges"])

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Components", data["total_components"])
    col2.metric("Scanned Components", data["scanned_components"])
    col3.metric("Vulnerable Components", data["vulnerable_components"])
    col4.metric("Highest CVSS", results_df["cvss"].max() if not results_df.empty else 0)

    st.subheader("Terminal-style Summary")
    summary_lines = [
        f"SBOM file             : {data['sbom_file']}",
        f"Total components      : {data['total_components']}",
        f"Scanned components    : {data['scanned_components']}",
        f"Vulnerable components : {data['vulnerable_components']}",
        "",
        "Top risky components:"
    ]

    for _, row in results_df.sort_values("risk_score", ascending=False).head(10).iterrows():
        summary_lines.append(
            f"{row['component']} {row['version']} | "
            f"{row['dependency_level']} | "
            f"CVE={row['cve_id'] or '-'} | "
            f"CVSS={row['cvss']} | "
            f"Risk={row['risk_score']}"
        )

    st.code("\n".join(summary_lines), language="text")

    st.subheader("Risk-Ranked Components")
    st.dataframe(
        results_df.sort_values("risk_score", ascending=False),
        use_container_width=True,
        hide_index=True,
    )

    if not results_df.empty:
        chart_df = results_df.sort_values("risk_score", ascending=False).head(10)
        fig = px.bar(
            chart_df,
            x="component",
            y="risk_score",
            hover_data=["cvss", "cve_id", "dependency_level", "severity"],
            title="Top 10 Components by Risk Score",
        )
        st.plotly_chart(fig, use_container_width=True)

    left, right = st.columns(2)

    with left:
        st.subheader("Dependency Level Distribution")
        dep_counts = results_df["dependency_level"].value_counts().reset_index()
        dep_counts.columns = ["dependency_level", "count"]
        fig2 = px.pie(dep_counts, names="dependency_level", values="count", title="Direct vs Transitive")
        st.plotly_chart(fig2, use_container_width=True)

    with right:
        st.subheader("Severity Distribution")
        sev_counts = results_df["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        fig3 = px.bar(sev_counts, x="severity", y="count", title="Severity Counts")
        st.plotly_chart(fig3, use_container_width=True)

    st.subheader("Dependency Edges")
    if edges_df.empty:
        st.info("No dependency edges found in the current SBOM.")
    else:
        st.dataframe(edges_df.head(100), use_container_width=True, hide_index=True)
