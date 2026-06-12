# dashboard/app.py

import streamlit as st
import pandas as pd
import plotly.express as px


st.markdown("""
<style>
.block-container {
    padding-top: 2rem;
}
</style>
""", unsafe_allow_html=True)


from streamlit_autorefresh import st_autorefresh



st_autorefresh(
    interval=5000,
    key="ids_refresh"
)

st.set_page_config(
    page_title="ML IDS Dashboard",
    page_icon="🛡",
    layout="wide"
)

st.title("🛡 Real-Time ML Intrusion Detection System")

try:
    df = pd.read_csv("../logs/alerts_session.csv")

    if len(df) == 0:
        st.info("No attacks detected in this IDS session yet.")
        st.stop()

except FileNotFoundError:
    st.warning("No session log found.")
    st.stop()
# ==========================
# Metrics
# ==========================

total_alerts = len(df)

portscan_count = len(
    df[df["prediction"] == "PORTSCAN"]
)

ssh_count = len(
    df[df["prediction"] == "SSH_BRUTEFORCE"]
)

unique_sources = df["src_ip"].nunique()

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Alerts", total_alerts)
col2.metric("Portscans", portscan_count)
col3.metric("SSH Brute Force", ssh_count)
col4.metric("Unique Sources", unique_sources)

st.divider()


# ==========================
# Timestamp Processing
# ==========================

df["timestamp"] = pd.to_datetime(df["timestamp"])

# ==========================
# Charts Row
# ==========================

left_col, right_col = st.columns(2)

with left_col:

    st.subheader("Attack Distribution")

    attack_counts = (
        df["prediction"]
        .value_counts()
        .reset_index()
    )

    attack_counts.columns = [
        "Attack Type",
        "Count"
    ]

    fig1 = px.pie(
        attack_counts,
        names="Attack Type",
        values="Count",
        hole=0.4
    )

    fig1.update_layout(
        template="plotly_dark"
    )

    st.plotly_chart(
        fig1,
        use_container_width=True
    )

with right_col:

    st.subheader("Alerts Timeline")

    timeline = (
        df.groupby("timestamp")
        .size()
        .reset_index(name="count")
    )

    fig2 = px.line(
        timeline,
        x="timestamp",
        y="count",
        markers=True
    )

    fig2.update_layout(
        template="plotly_dark"
    )

    st.plotly_chart(
        fig2,
        use_container_width=True
    )

st.divider()

st.subheader("Recent Alerts")

recent_df = df.sort_values(
    by="timestamp",
    ascending=False
)

st.dataframe(
    recent_df,
    use_container_width=True,
    hide_index=True
)

st.divider()

st.download_button(
    label="📥 Download Session Logs",
    data=df.to_csv(index=False),
    file_name="alerts_session.csv",
    mime="text/csv"
)


