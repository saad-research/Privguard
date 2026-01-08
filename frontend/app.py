import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import json
import os
import time
from datetime import datetime


API_URL = "http://127.0.0.1:8000"

# Adjust paths to point to the Security folder in the root directory
ATTACKS_FILE = os.path.join("Security", "attacks.csv")
LOG_FILE = os.path.join("Security", "audit_log.jsonl")

# -----------------------------
# PAGE CONFIG
# -----------------------------
st.set_page_config(
    page_title="PrivGuard Enterprise DLP",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title(" PrivGuard — AI Privacy & Security Gateway ")
st.caption("Hybrid Routing • RBAC Policies • Tamper-Proof Audit Chain")

tab1, tab2, tab3 = st.tabs([
    " Live Inspector",
    " Vulnerability Scanner ",
    " SOC Dashboard "
])



# --- SIDEBAR: CONTEXT SWITCHER ---
st.sidebar.divider()
st.sidebar.title("PrivGuard")
st.sidebar.caption("AI Security Gateway v0.2")
st.sidebar.markdown("---")

# User Context Simulator
st.sidebar.subheader("User Simulation")
user_role = st.sidebar.selectbox(
    "Active Role",
    ["Student", "Researcher", "Employee", "Admin"]
)

st.sidebar.info(f"**Policy Active: {user_role.upper()}**\n\n"
                "• **Student**: Strict Block (PII/Secrets)\n"
                "• **Researcher**: Redact PII, Local Route\n"
                "• **Employee**: Standard Corporate Policy")

st.sidebar.markdown("---")
st.sidebar.metric("System Status", "ONLINE", "Latency: 45ms")


# ==========================================
# TAB 1: LIVE INSPECTOR (Single Request)
# ==========================================

with tab1:
    st.subheader("⚡ Real-Time Traffic Inspector")
    st.markdown("Use this console to inspect a single prompt's journey through the security pipeline.")
    text = st.text_area("Enter prompt:", height=140, placeholder="e.g., Here is my API key sk-test-12345...")

    col1, col2 = st.columns(2)

    with col1:
        run_btn = st.button("Scan Request", type="primary")

    if run_btn and text.strip():

        # Call the API
        resp = requests.post(
            f"{API_URL}/proxy",
            json={"text": text, "user_role": user_role},
            headers={"x-user-role": user_role}
        )

        # Display Results
        data = resp.json()

        st.write("### Gateway Decision")
        st.json(data)

        # Soft KPIs panel
        k1, k2, k3 = st.columns(3)
        k1.metric("Risk Level", data.get("risk_level", "—"))
        k2.metric("Action", data.get("action", "—"))
        k3.metric("Route", data.get("action", "—").replace("ROUTED_TO_", ""))

        st.success("Event recorded in tamper-proof audit log.")

    with col2:
        st.markdown("**Quick Test Vectors:**")
        if st.button("📝 Test: Student PII"):
             st.code("{'text':'My email is student@uni.edu'}", language="text")
        if st.button("🔑 Test: API Key Leak"):
             st.code("{'text':'Here is our API key sk-test-123456'}", language="text")
        if st.button("🕵️ Test: Internal Data"):
             st.code("{'text':'CONFIDENTIAL: Patent draft V1'}", language="text")


# -------------------------------------------------
# TAB 2: BATCH SCANNER (The Attacks.csv)
# -------------------------------------------------
with tab2:

    st.subheader("🧪 Automated Red-Team Attack Suite")
    st.markdown("Batch-process the `attacks.csv` Red Team dataset to validate policy compliance.")


    if os.path.exists(ATTACKS_FILE):
        df_attacks = pd.read_csv(ATTACKS_FILE)
        df_attacks.index = range(1, len(df_attacks) + 1)

        # Show Preview
        with st.expander("View Attack Dataset Source", expanded=False):
            st.dataframe(df_attacks.head(20), use_container_width=True)
        
        col_metric1, col_metric2 = st.columns(2)
        col_metric1.metric("Total Test Attacks(Vectors)", len(df_attacks))

        if st.button(f"🚀 Run Full Compliance Scan"):

            results = []
            progress_bar = st.progress(0)
            status_text = st.empty()

            total = len(df_attacks)

            # Iterate through attacks
            for index, row in df_attacks.iterrows():
                # Update UI
                progress_bar.progress(index / total)
                status_text.text(f"Scanning {row['attack_id']} ({row['attack_type']})...")

                try:
                    payload = {"text": row['prompt'], "user_role": row['role']}
                    headers = {"x-user-role": row['role']}

                # Execute Request
                    resp = requests.post(f"{API_URL}/proxy", json=payload, headers=headers)
                    data = resp.json()

                    actual_action = data.get("action", "ERROR")
                    expected = row['expected_action'].upper()


                    # LOGIC: Did PrivGuard do what the CSV expected?
                    # We do a loose string match (e.g. if CSV says "BLOCK" and API says "BLOCKED_BY_POLICY" -> PASS)

                    is_pass = (
                        expected in actual_action.upper() 
                        or (expected == "ALLOW" and "ROUTED" in actual_action.upper())
                    )
                    status = "✅ PASS" if is_pass else "❌ FAIL"

                    results.append({
                    "Attack ID": row['attack_id'],
                    "Type": row['attack_type'],
                    "Role": row['role'],
                    "Expected": expected,
                    "Actual": actual_action,
                    "Status": status
                    })

                    # Optional visual delay
                    # time.sleep(0.03)

                except Exception as e:
                    results.append({
                        "Attack ID": row["attack_id"],
                        "Type": row["attack_type"],
                        "Role": row["role"],
                        "Expected": row["expected_action"],
                        "Actual": "ERROR",
                        "Status": "⚠️ ERROR"
                    })

            # Scan Complete
            status_text.success("Scan Complete!")
            results_df = pd.DataFrame(results)
            results_df.index = range(1, len(results_df) + 1)

            # Metrics
            st.write("### Test Results ")

            pass_count = len(results_df[results_df["Status"] == "✅ PASS"])
            pass_rate = pass_count / len(results_df)
            col_metric2.metric("Defense Success Rate", f"{pass_rate*100:.0f}%")

            # Display Results Table
            st.dataframe(results_df, use_container_width=True)

            st.info("All actions + routing decisions were also recorded in audit log.")

    else:
        st.warning(f"⚠️ Could not find attack dataset at `{ATTACKS_FILE}`. Please check file path.")


# ==========================================
# TAB 3 — SECURITY OPERATIONS DASHBOARD
# ==========================================

with tab3:

    st.header("📊 Security Operations Center (SOC)")
    st.markdown("Real-time visibility into blocked threats and policy decisions.")

    # Refresh Button
    if st.button("🔄 Refresh Logs"):
        st.rerun()

    if os.path.exists(LOG_FILE):

        # Read JSONL file line by line
        log_data = []
        try:    
            with open(LOG_FILE, "r") as f:
                for line in f:
                    if line.strip():
                        log_data.append(json.loads(line))

        except Exception as e:
            st.error(f"Error reading logs: {e}")

        if log_data:
            df_logs = pd.DataFrame(log_data)
            df_logs.index = range(1, len(df_logs) + 1)

            # 1. TOP METRICS
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Requests", len(df_logs))
            
            blocked_count = len(df_logs[df_logs['policy_action'] == 'BLOCK'])
            m2.metric("Attacks Blocked", blocked_count, delta="Shield Active", delta_color="normal")
            
            critical_count = len(df_logs[df_logs['detected_risk_level'] == 'CRITICAL'])
            m3.metric("Critical Incidents", critical_count, delta="High Risk", delta_color="inverse")
            
            sovereign_count = len(df_logs[df_logs['routing_decision'] == 'SAFE_MODE'])
            m4.metric("Sovereign/Local Routes", sovereign_count)

            st.markdown("---")

            # 2. CHARTS ROW
            c1, c2 = st.columns(2)

            with c1:
                st.subheader("⚠️ Threat Landscape")
                if not df_logs.empty:
                    risk_counts = df_logs['detected_risk_level'].value_counts()
                    fig_risk = px.pie(
                        values=risk_counts.values, 
                        names=risk_counts.index, 
                        title="Distribution of Risk Levels",
                        hole=0.4,
                        color_discrete_map={"CRITICAL": "darkred", "HIGH": "red", "MEDIUM": "orange", "LOW": "green"}
                    )
                    st.plotly_chart(fig_risk, use_container_width=True)
            
            with c2:
                st.subheader("🛡️ Policy Actions Over Time")
                if not df_logs.empty:
                    fig_action = px.bar(
                        df_logs, x='user_role', color='policy_action', 
                        title="Actions by User Role",
                        color_discrete_map={"ALLOW": "green", "REDACT": "orange", "BLOCK": "red", "ROUTED_TO_LOCAL_MODEL": "blue"}
                    )
                    st.plotly_chart(fig_action, use_container_width=True)
            
            st.divider()

            # ---------- Hash Chain Table ----------
            st.subheader(" Tamper-Proof Audit Trail")
            st.caption("Each log entry is chained using SHA-256 to prevent tampering.")

            # Show specific columns
            st.dataframe(
                df_logs[
                    [
                        "timestamp_utc",
                        "user_role",
                        "detected_risk_level",
                        "policy_action",
                        "routing_decision",
                        "current_log_hash"
                    ]
                ].sort_values(by="timestamp_utc", ascending=False),
                use_container_width=True
            )

        else:
            st.info("Log file is empty. Go to Tab 1 or 2 to generate traffic.")
            
    else:
        st.warning("⚠️ No audit logs found. System is waiting for traffic.")
