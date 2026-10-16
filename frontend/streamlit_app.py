"""Streamlit dashboard for the privacy-native vSOC."""

import streamlit as st
import requests
import pandas as pd
from datetime import datetime

BACKEND_URL = "http://localhost:8000"

st.set_page_config(page_title="Privacy-Native vSOC", page_icon="🛡️", layout="wide")

st.title("🛡️ Privacy-Native vSOC for Connected Vehicles")
st.markdown(
    "CAN-bus attack detection with privacy-preserving vehicle identities, "
    "location minimization, dual-approval unmasking, and tamper-evident audit."
)

st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Dashboard", "Detection", "Privacy / Unmask", "Audit Log", "Anomaly Warnings"])


def api_get(path, params=None):
    try:
        r = requests.get(f"{BACKEND_URL}{path}", params=params, timeout=5)
        if r.status_code == 200:
            return r.json()
        st.error(f"API error {r.status_code}: {r.text}")
        return None
    except Exception as e:
        st.error(f"Cannot connect to backend: {e}")
        return None


def api_post(path, json_data=None):
    try:
        r = requests.post(f"{BACKEND_URL}{path}", json=json_data, timeout=5)
        if r.status_code in (200, 201):
            return r.json()
        st.error(f"API error {r.status_code}: {r.text}")
        return None
    except Exception as e:
        st.error(f"Cannot connect to backend: {e}")
        return None


# Health check (sidebar)
health = api_get("/health")
if health:
    st.sidebar.success(f"Backend: {health.get('status', 'unknown')}")
    st.sidebar.caption(f"Model loaded: {health.get('model_loaded', False)}")
else:
    st.sidebar.error("Backend unreachable")


# ============================================================================
# Page: Dashboard
# ============================================================================
if page == "Dashboard":
    st.header("📊 Dashboard")
    st.info(
        "Privacy notice: All vehicle identifiers shown below are pseudonymous tokens. "
        "Real driver identities and precise GPS coordinates are never displayed "
        "in ordinary analyst views."
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Audit Events", "—")
    with col2:
        st.metric("Attack Alerts", "—")
    with col3:
        st.metric("Pending Unmask Requests", "—")

    st.subheader("Recent Attack Alerts")
    events = api_get("/audit/events", params={"event_type": "attack_alert", "limit": 20})
    if events and events.get("events"):
        df = pd.DataFrame(events["events"])
        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            st.dataframe(
                df[["timestamp", "actor", "outcome", "details"]],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.write("No attack alerts recorded yet.")
    else:
        st.write("No attack alerts recorded yet.")

# ============================================================================
# Page: Detection
# ============================================================================
if page == "Detection":
    st.header("🔍 CAN-bus Attack Detection")
    st.markdown("Submit a CAN bus frame for attack classification.")

    with st.form("detect_form"):
        col1, col2 = st.columns(2)
        with col1:
            timestamp = st.number_input("Timestamp", value=1478198376.389427, format="%.6f")
            arbitration_id = st.text_input("Arbitration ID (hex)", value="0316")
            dlc = st.number_input("DLC", min_value=0, max_value=15, value=8)
        with col2:
            data_bytes = st.text_input(
                "Data bytes (hex, comma-separated)",
                value="05,21,68,09,21,21,00,6f",
            )
            vehicle_token = st.text_input("Vehicle token (optional)", value="")

        submitted = st.form_submit_button("Detect")

    if submitted:
        try:
            db_list = [int(b.strip(), 16) for b in data_bytes.split(",") if b.strip()]
        except ValueError:
            st.error("Invalid data bytes format. Use hex values separated by commas.")
            db_list = []

        payload = {
            "frame": {
                "timestamp": timestamp,
                "arbitration_id": arbitration_id,
                "dlc": dlc,
                "data_bytes": db_list,
            },
            "vehicle_token": vehicle_token or None,
        }

        result = api_post("/detect", json_data=payload)
        if result:
            st.success(f"Prediction: **{result['prediction']}** (confidence: {result['confidence']:.4f})")
            if result["prediction"] != "Normal":
                st.warning(f"⚠️ Attack detected: {result['prediction']}")
            with st.expander("Features"):
                st.json(result.get("features", {}))

# ============================================================================
# Page: Privacy / Unmask
# ============================================================================
elif page == "Privacy / Unmask":
    st.header("🔐 Privacy & Identity Unmasking")

    tab1, tab2, tab3 = st.tabs(["Tokenize Vehicle", "Location Minimization", "Unmask Request"])

    with tab1:
        st.subheader("Pseudonymous Token Generation")
        st.markdown(
            "Real vehicle IDs are never stored or transmitted in alerts. "
            "Tokens are HMAC-SHA256 derived and rotate every 24 hours."
        )
        vid = st.text_input("Vehicle ID (VIN)", value="VIN-DEMO-12345")
        if st.button("Generate Token"):
            result = api_post("/privacy/tokenize", json_data={"vehicle_id": vid})
            if result:
                st.code(f"Token: {result['vehicle_token']}")
                st.caption(f"Rotation epoch: {result['rotation_epoch']}")

    with tab2:
        st.subheader("Location Minimization")
        st.markdown(
            "Coordinates are coarsened or withheld by policy. "
            "Ordinary analysts never see precise GPS."
        )
        lat = st.number_input("Latitude", value=40.7128, format="%.6f")
        lon = st.number_input("Longitude", value=-74.0060, format="%.6f")
        level = st.selectbox("Minimization level", ["coarsen", "withhold", "none"])
        if st.button("Apply Minimization"):
            result = api_post(
                "/privacy/location/coarsen",
                json_data={"latitude": lat, "longitude": lon, "minimization_level": level},
            )
            if result:
                st.json(result)

    with tab3:
        st.subheader("Dual-Approval Unmasking")
        st.markdown(
            "Two distinct security officers must approve before a vehicle "
            "identity can be revealed. Duplicate approvals are rejected."
        )
        token = st.text_input("Vehicle token to unmask")
        justification = st.text_area("Justification (min 10 chars)", value="Investigating suspected attack")
        requester = st.text_input("Requested by (security officer)", value="sec_officer_1")

        if st.button("Request Unmask"):
            if len(justification) < 10:
                st.error("Justification must be at least 10 characters")
            else:
                result = api_post(
                    "/privacy/unmask/request",
                    json_data={
                        "vehicle_token": token,
                        "justification": justification,
                        "requested_by": requester,
                    },
                )
                if result:
                    st.json(result)

        st.divider()
        st.subheader("Approve / Reject Request")
        req_id = st.text_input("Request ID")
        approver = st.text_input("Approver (security officer)", value="sec_officer_2")
        action = st.selectbox("Action", ["Approve", "Reject"])
        if st.button("Submit Decision"):
            result = api_post(
                "/privacy/unmask/approve",
                json_data={
                    "request_id": req_id,
                    "approver_user_id": approver,
                    "approve": action == "Approve",
                },
            )
            if result:
                st.json(result)

# ============================================================================
# Page: Audit Log
# ============================================================================
elif page == "Audit Log":
    st.header("📋 Tamper-Evident Audit Log")
    st.markdown(
        "All security-relevant events are recorded in a hash-chained log. "
        "Any modification, deletion, or reordering is detectable."
    )

    col1, col2 = st.columns([3, 1])
    with col1:
        if st.button("Verify Chain Integrity"):
            result = api_get("/audit/verify")
            if result:
                if result["chain_valid"]:
                    st.success(
                        f"✅ Chain valid: {result['verified_records']}/{result['total_records']} records verified"
                    )
                else:
                    st.error(f"❌ Chain compromised: {result['tampered_records']}")
                st.json(result)

    with col2:
        if st.button("Test Tamper Detection"):
            result = api_post("/audit/verify/tamper")
            if result:
                if result["chain_valid"]:
                    st.success("Chain still valid (no tampering detected)")
                else:
                    st.error(f"❌ Tampering detected: {result['tampered_records']}")

    st.subheader("Recent Audit Events")
    events = api_get("/audit/events", params={"limit": 30})
    if events and events.get("events"):
        df = pd.DataFrame(events["events"])
        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            st.dataframe(
                df[["timestamp", "event_type", "actor", "outcome"]],
                use_container_width=True,
                hide_index=True,
            )
    else:
        st.write("No audit events yet.")

# ============================================================================
# Page: Anomaly Warnings
# ============================================================================
elif page == "Anomaly Warnings":
    st.header("⚠️ Access Anomaly Warnings")
    st.markdown(
        "These are explainable threshold-based rules (not AI). "
        "They flag suspicious access patterns for auditor review."
    )

    result = api_get("/anomaly/warnings")
    if result:
        warnings = result.get("warnings", [])
        st.metric("Active Warnings", result.get("count", 0))
        if warnings:
            for w in warnings:
                severity_color = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(w["severity"], "⚪")
                st.warning(
                    f"{severity_color} **{w['rule_name']}** — User: `{w['user_id']}`\n\n"
                    f"{w['description']}\n\n"
                    f"First: {w['first_occurrence']} | Last: {w['last_occurrence']}"
                )
        else:
            st.info("No anomaly warnings at this time.")

st.divider()
st.caption(
    "Privacy-Native vSOC — IBM Z Datathon 2026 | "
    "Demo data only. No real PII or vehicle telemetry."
)