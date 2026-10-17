import streamlit as st
import plotly.express as px

from analyzer import load_audit_logs, analyze_events

st.set_page_config(
    page_title="Cloud IAM Security Analyzer",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Cloud Security Posture & IAM Analyzer")
st.caption("Analyze cloud audit logs and identify potentially risky activity.")

# Load and analyze events
try:
    events = load_audit_logs()
    analyzed = analyze_events(events)
except (OSError, ValueError, KeyError) as error:
    st.error(f"Could not load audit logs: {error}")
    st.stop()

if analyzed.empty:
    st.warning("No audit events found.")
    st.stop()

# Sidebar filters
st.sidebar.header("Filter Events")

users = sorted(analyzed["user"].dropna().unique().tolist())
selected_users = st.sidebar.multiselect(
    "Users",
    options=users,
    default=users,
)

severities = ["High", "Medium", "Low", "Informational"]
available_severities = [
    severity
    for severity in severities
    if severity in analyzed["severity"].values
]
selected_severities = st.sidebar.multiselect(
    "Severity",
    options=available_severities,
    default=available_severities,
)

event_types = sorted(analyzed["event_name"].dropna().unique().tolist())
selected_events = st.sidebar.multiselect(
    "Event types",
    options=event_types,
    default=event_types,
)

filtered = analyzed[
    analyzed["user"].isin(selected_users)
    & analyzed["severity"].isin(selected_severities)
    & analyzed["event_name"].isin(selected_events)
].copy()

# Summary metrics
total_events = len(filtered)
high_risk = int((filtered["severity"] == "High").sum())
flagged_events = int((filtered["risk_score"] > 0).sum())
average_risk = (
    round(float(filtered["risk_score"].mean()), 1)
    if total_events
    else 0
)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Audit Events", total_events)
col2.metric("High-Risk Events", high_risk)
col3.metric("Flagged Events", flagged_events)
col4.metric("Average Risk Score", average_risk)

st.divider()

# Charts
left, right = st.columns(2)

with left:
    st.subheader("Events by Severity")

    if filtered.empty:
        st.info("No events match the selected filters.")
    else:
        severity_counts = (
            filtered["severity"]
            .value_counts()
            .reindex(severities, fill_value=0)
            .rename_axis("Severity")
            .reset_index(name="Count")
        )

        figure = px.bar(
            severity_counts,
            x="Severity",
            y="Count",
            title="Security Event Severity",
        )
        st.plotly_chart(figure, use_container_width=True)

with right:
    st.subheader("Risk Score Distribution")

    if filtered.empty:
        st.info("No risk scores to display.")
    else:
        figure = px.histogram(
            filtered,
            x="risk_score",
            nbins=10,
            title="Distribution of Risk Scores",
        )
        st.plotly_chart(figure, use_container_width=True)

# Audit event table
st.divider()
st.subheader("Audit Event Details")

display_columns = [
    column
    for column in [
        "event_id",
        "timestamp",
        "user",
        "source_ip",
        "event_name",
        "status",
        "role",
        "risk_score",
        "severity",
        "findings",
    ]
    if column in filtered.columns
]

st.dataframe(
    filtered[display_columns],
    use_container_width=True,
    hide_index=True,
)

# Download filtered results
csv_data = filtered.to_csv(index=False).encode("utf-8")

st.download_button(
    label="Download Filtered Events as CSV",
    data=csv_data,
    file_name="security_audit_report.csv",
    mime="text/csv",
)

st.caption(
    "Training prototype: risk scores are rule-based indicators, "
    "not proof of a security incident."
)
