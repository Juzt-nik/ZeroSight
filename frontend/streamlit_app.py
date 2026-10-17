"""Seven-scene authenticated Streamlit demonstration for the vSOC API."""

import os
import time

import pandas as pd
import requests
import streamlit as st

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")
TIMEOUT_SECONDS = 15

st.set_page_config(page_title="Privacy-Native vSOC", page_icon="🛡️", layout="wide")
st.title("Privacy-Native vSOC for Connected Vehicles")
st.caption("Seven repeatable scenes backed by the authenticated FastAPI service")

st.sidebar.header("Backend connection")
st.sidebar.text_input("Backend URL", value=BACKEND_URL, key="backend_url")
st.sidebar.text_input(
    "Bearer token", type="password", key="api_token",
    help="Paste a server-issued JWT. In DEMO_MODE, use user_id:role, e.g. analyst_1:analyst.",
)
st.sidebar.caption("Roles are read from the authenticated backend principal.")


def api_request(method, path, *, params=None, payload=None):
    token = st.session_state.get("api_token", "").strip()
    if not token:
        st.error("Enter a bearer token in the sidebar to call protected API routes.")
        return None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    try:
        response = requests.request(
            method, f"{st.session_state.get('backend_url', BACKEND_URL).rstrip('/')}{path}",
            headers=headers, params=params, json=payload, timeout=TIMEOUT_SECONDS,
        )
        if not response.ok:
            try:
                detail = response.json().get("error", response.text)
            except ValueError:
                detail = response.text
            st.error(f"{method} {path} returned {response.status_code}: {detail}")
            return None
        return response.json() if response.content else {}
    except requests.RequestException as exc:
        st.error(f"Backend request failed: {exc}")
        return None


try:
    health = requests.get(f"{st.session_state.get('backend_url', BACKEND_URL).rstrip('/')}/health", timeout=5)
    if health.ok:
        health_data = health.json()
        st.sidebar.success(f"Backend: {health_data.get('status', 'unknown')}")
        st.sidebar.caption(f"Model loaded: {health_data.get('model_loaded', False)}")
    else:
        st.sidebar.error("Backend health check failed")
except requests.RequestException:
    st.sidebar.error("Backend unreachable")

principal = api_request("GET", "/access/me")
if principal:
    st.sidebar.info(f"Signed in as {principal['user_id']} · {', '.join(principal['roles'])}")

scene = st.sidebar.radio("Demo scene", [
    "1 · Detect CAN attack", "2 · Tokenize vehicle", "3 · Minimize location",
    "4 · Request unmask", "5 · Approve unmask", "6 · Audit and anomalies",
    "7 · Metrics and load results",
])

if scene == "1 · Detect CAN attack":
    st.header(scene)
    st.write("Submit one CAN frame to the model. Attack predictions are written to the audit log.")
    with st.form("detect"):
        timestamp = st.number_input("Unix timestamp", value=1478198376.389427, format="%.6f")
        arbitration_id = st.text_input("Arbitration ID (hex)", "0316")
        dlc = st.number_input("DLC", min_value=0, max_value=15, value=8)
        raw_bytes = st.text_input("Data bytes (hex, comma separated)", "05,21,68,09,21,21,00,6f")
        vehicle_token = st.text_input("Vehicle token (optional)")
        submit = st.form_submit_button("Run detection")
    if submit:
        try:
            data_bytes = [int(value.strip(), 16) for value in raw_bytes.split(",") if value.strip()]
            started = time.perf_counter()
            result = api_request("POST", "/detect", payload={"frame": {
                "timestamp": timestamp, "arbitration_id": arbitration_id,
                "dlc": int(dlc), "data_bytes": data_bytes,
            }, "vehicle_token": vehicle_token or None})
            elapsed = (time.perf_counter() - started) * 1000
            if result:
                st.metric("Prediction", result["prediction"])
                st.metric("Confidence", f"{result['confidence']:.4f}")
                st.metric("Server inference", f"{result.get('inference_latency_ms', 0):.2f} ms")
                st.metric("HTTP round trip", f"{elapsed:.2f} ms")
                st.json(result)
        except ValueError:
            st.error("Enter each data byte as a hexadecimal value.")

elif scene == "2 · Tokenize vehicle":
    st.header(scene)
    st.warning("Demo only: use synthetic identifiers; the submitted ID is sensitive input.")
    with st.form("tokenize"):
        vehicle_id = st.text_input("Synthetic vehicle ID", "SYNTHETIC-VEHICLE-001")
        context = st.text_input("Context (optional)")
        submit = st.form_submit_button("Generate pseudonymous token")
    if submit:
        result = api_request("POST", "/privacy/tokenize", payload={"vehicle_id": vehicle_id, "context": context or None})
        if result:
            st.success(f"Vehicle token: {result['vehicle_token']}")
            st.json(result)

elif scene == "3 · Minimize location":
    st.header(scene)
    with st.form("location"):
        latitude = st.number_input("Latitude", value=40.7128, min_value=-90.0, max_value=90.0, format="%.6f")
        longitude = st.number_input("Longitude", value=-74.0060, min_value=-180.0, max_value=180.0, format="%.6f")
        level = st.selectbox("Policy", ["coarsen", "withhold", "none"])
        submit = st.form_submit_button("Apply minimization")
    if submit:
        result = api_request("POST", "/privacy/location/coarsen", payload={
            "latitude": latitude, "longitude": longitude, "minimization_level": level,
        })
        if result:
            st.json(result)

elif scene == "4 · Request unmask":
    st.header(scene)
    st.info("Requires the security_officer role. Requester identity comes from the bearer token.")
    with st.form("unmask_request"):
        token = st.text_input("Vehicle token")
        justification = st.text_area("Justification (at least 10 characters)", "Investigating a synthetic vehicle alert")
        submit = st.form_submit_button("Request unmask")
    if submit:
        result = api_request("POST", "/privacy/unmask/request", payload={"vehicle_token": token, "justification": justification})
        if result:
            st.session_state["last_unmask_request_id"] = result["request_id"]
            st.success("Request submitted. A distinct officer must approve it.")
            st.json(result)

elif scene == "5 · Approve unmask":
    st.header(scene)
    st.info("Requires a distinct security_officer principal. Approver identity comes from the bearer token.")
    request_id = st.text_input("Request ID", st.session_state.get("last_unmask_request_id", ""))
    decision = st.selectbox("Decision", ["Approve", "Reject"])
    if st.button("Submit decision"):
        result = api_request("POST", "/privacy/unmask/approve", payload={"request_id": request_id, "approve": decision == "Approve"})
        if result:
            st.json(result)

elif scene == "6 · Audit and anomalies":
    st.header(scene)
    tab_audit, tab_anomaly = st.tabs(["Audit trail", "Access anomalies"])
    with tab_audit:
        if st.button("Verify audit chain"):
            result = api_request("GET", "/audit/verify")
            if result:
                (st.success if result["chain_valid"] else st.error)(
                    f"Chain {'valid' if result['chain_valid'] else 'compromised'} · {result['verified_records']}/{result['total_records']} verified"
                )
                st.json(result)
        if st.button("Run destructive tamper demonstration"):
            st.warning("This endpoint modifies a stored audit row and is for disposable demo data only.")
            result = api_request("POST", "/audit/verify/tamper", payload={})
            if result:
                st.json(result)
        events = api_request("GET", "/audit/events", params={"limit": 30})
        if events and events.get("events"):
            st.dataframe(pd.DataFrame(events["events"]), use_container_width=True, hide_index=True)
    with tab_anomaly:
        st.write("Record a demo access event for your authenticated account. The backend rejects events attributed to another user.")
        with st.form("record_access_event"):
            event_action = st.selectbox("Access action", ["login", "unmask_request", "detect:create"])
            event_outcome = st.selectbox("Outcome", ["denial", "success"])
            record_event = st.form_submit_button("Record my access event")
        if record_event and principal:
            result = api_request(
                "POST", "/anomaly/record-event",
                params={"user_id": principal["user_id"], "action": event_action, "outcome": event_outcome},
            )
            if result:
                st.success(f"Recorded event for {result['user_id']}")
        if st.button("Load anomaly warnings"):
            result = api_request("GET", "/anomaly/warnings")
            if result:
                st.metric("Active warnings", result["count"])
                if result["warnings"]:
                    st.dataframe(pd.DataFrame(result["warnings"]), use_container_width=True, hide_index=True)
                else:
                    st.info("No active warnings.")

else:
    st.header(scene)
    st.write("Model evaluation metrics are loaded from the deployed model. HTTP round-trip timing is measured by this dashboard.")
    if st.button("Fetch model metrics"):
        metrics = api_request("GET", "/detect/metrics")
        if metrics:
            cols = st.columns(4)
            for col, label in zip(cols, ["accuracy", "precision_macro", "recall_macro", "f1_macro"]):
                col.metric(label.replace("_", " ").title(), metrics[label])
            st.subheader("Per-class metrics")
            st.dataframe(pd.DataFrame(metrics["per_class"]).T, use_container_width=True)
            st.caption("False-positive rate is not exposed by this API contract. The load runner computes it from labeled requests when ground truth is supplied.")
            st.json({"confusion_matrix": metrics["confusion_matrix"], "classes": metrics["classes"], "training_samples": metrics["training_samples"], "test_samples": metrics["test_samples"]})
    st.subheader("Load-test artifacts")
    st.caption("Run the documented end-to-end command; results are saved as JSON and summarized in docs/path-to-production.md.")

st.divider()
st.caption("Synthetic demo data only · Streamlit sends Authorization: Bearer <token> on protected API calls")
