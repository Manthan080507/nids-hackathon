import streamlit as st
import pandas as pd
import psutil
import socket
import json
import time

# Page Setup
st.set_page_config(page_title="NIDS Real-Time Security Hub", page_icon="🛡️", layout="wide")

# Load model weights
@st.cache_data
def load_model():
    try:
        with open('nids_model.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {'threshold_failed_logins': 0, 'threshold_wrong_fragment': 0, 'threshold_src_bytes': 40000}

model = load_model()

# Header & Top Navigation Bar
st.title("🛡️ Real-Time Network Intrusion Detection System")
st.caption("Live Local Traffic Sniffer • CSV Dataset Inspector • Real Threat Intelligence")

# Top Menu Tabs
tab_dash, tab_sniff, tab_single, tab_csv, tab_analytics = st.tabs([
    "🏠 Dashboard", 
    "📡 Live Machine Network Sniffer", 
    "🔍 Test Custom Packet", 
    "📁 Upload CSV Dataset", 
    "📊 Real System Traffic Analytics"
])

# ==========================================
# TAB 1: DASHBOARD OVERVIEW
# ==========================================
with tab_dash:
    st.header("Local Network Gateway Status")
    
    # Real network stats from user's machine using psutil
    net_io = psutil.net_io_counters()
    bytes_sent_mb = net_io.bytes_sent / (1024 * 1024)
    bytes_recv_mb = net_io.bytes_recv / (1024 * 1024)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("System Hostname", socket.gethostname())
    col2.metric("Total Bytes Sent", f"{bytes_sent_mb:.2f} MB")
    col3.metric("Total Bytes Received", f"{bytes_recv_mb:.2f} MB")
    col4.metric("Active Connections", len(psutil.net_connections()))

    st.divider()
    st.subheader("System Modules")
    
    c1, c2, c3 = st.columns(3)
    with c1:
        st.info("### 📡 Live Machine Sniffer\nCaptures real active network socket connections running on your computer right now.")
    with c2:
        st.success("### 🔍 Single Packet Inspector\nManually inspect specific packet parameters to calculate threat vectors.")
    with c3:
        st.warning("### 📁 Batch Scan Dataset\nUpload historical CSV packet logs (like NSL-KDD) for bulk threat detection.")

# ==========================================
# TAB 2: LIVE MACHINE NETWORK SNIFFER (REAL DATA)
# ==========================================
with tab_sniff:
    st.header("📡 Live Machine Network Interface Sniffer")
    st.write("This tool monitors active connection sockets directly on your machine in real time.")

    sniff_active = st.toggle("Start Live Socket Capture", value=False)
    sniff_container = st.empty()

    if sniff_active:
        real_records = []
        # Capture live active net connections on localhost/network card
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr and conn.status == 'ESTABLISHED':
                l_host, l_port = conn.laddr
                r_host, r_port = conn.raddr
                
                # Check real bytes/packet metrics
                is_suspicious_port = r_port in [22, 23, 3389, 445]  # Common attack vectors (SSH, Telnet, RDP, SMB)
                verdict = "🚨 ATTACK / SUSPICIOUS" if is_suspicious_port else "✅ NORMAL"
                category = "Port Probe / Suspicious Service" if is_suspicious_port else "Standard Web / Socket Connection"

                real_records.append({
                    "Timestamp": time.strftime("%H:%M:%S"),
                    "Local Address": f"{l_host}:{l_port}",
                    "Remote Address (IP)": f"{r_host}:{r_port}",
                    "Socket Status": conn.status,
                    "Process ID (PID)": conn.pid if conn.pid else "System",
                    "Verdict": verdict,
                    "Threat Category": category
                })

        if real_records:
            df_real = pd.DataFrame(real_records)
            with sniff_container.container():
                st.subheader(f"Active Live Sockets Captured: {len(df_real)}")
                st.dataframe(df_real, use_container_width=True)
        else:
            with sniff_container.container():
                st.info("Listening on network interfaces... Open a web browser page or connect to a service to see active socket connections appear.")

# ==========================================
# TAB 3: TEST SINGLE PACKET
# ==========================================
with tab_single:
    st.header("🔍 Single Packet Payload Inspector")
    st.write("Test custom network parameters against your model's classification logic.")

    col_a, col_b = st.columns(2)
    with col_a:
        duration = st.number_input("Connection Duration (sec)", 0.0, 100.0, 1.0)
        src_bytes = st.number_input("Source Bytes Sent", 0, 100000, 1200)
        dst_bytes = st.number_input("Destination Bytes Received", 0, 100000, 3000)
    
    with col_b:
        wrong_fragment = st.selectbox("Wrong Fragment Count", [0, 1, 2])
        failed_logins = st.selectbox("Failed Password Attempts", [0, 1, 2, 3, 4, 5])
        st.write("")
        analyze_btn = st.button("🚀 Analyze Packet", type="primary")

    if analyze_btn:
        st.divider()
        is_attack = failed_logins > model['threshold_failed_logins'] or wrong_fragment > model['threshold_wrong_fragment'] or src_bytes > model['threshold_src_bytes']

        if is_attack:
            st.error("🚨 ATTACK TRAFFIC DETECTED!")
            if failed_logins > 0:
                st.write("• **Reason:** Failed password attempts detected (Brute-Force Attack).")
            if wrong_fragment > 0:
                st.write("• **Reason:** Corrupted fragments detected (Denial of Service).")
            if src_bytes > 40000:
                st.write("• **Reason:** Unusually large data transfer spike detected.")
        else:
            st.success("✅ CLEAN / NORMAL TRAFFIC")
            st.write("This connection follows expected normal behavior.")

# ==========================================
# TAB 4: UPLOAD CSV DATASET
# ==========================================
with tab_csv:
    st.header("📁 Bulk Dataset Scanner")
    uploaded_file = st.file_uploader("Upload CSV Network Log File", type=["csv"])

    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        st.write("Uploaded File Preview:")
        st.dataframe(df.head())

        if st.button("Run Bulk Analysis", type="primary"):
            def evaluate(row):
                fl = row.get('num_failed_logins', row.get('failed_logins', 0))
                wf = row.get('wrong_fragment', 0)
                sb = row.get('src_bytes', 0)
                if fl > model['threshold_failed_logins'] or wf > model['threshold_wrong_fragment'] or sb > model['threshold_src_bytes']:
                    return "ATTACK 🚨"
                return "NORMAL ✅"

            df['Verdict'] = df.apply(evaluate, axis=1)
            
            total = len(df)
            attacks = (df['Verdict'] == "ATTACK 🚨").sum()
            normal = total - attacks

            m1, m2, m3 = st.columns(3)
            m1.metric("Total Rows Evaluated", total)
            m2.metric("Attacks Found 🚨", attacks)
            m3.metric("Normal Connections ✅", normal)

            st.dataframe(df, use_container_width=True)

# ==========================================
# TAB 5: REAL SYSTEM TRAFFIC ANALYTICS
# ==========================================
with tab_analytics:
    st.header("📊 Real System Traffic Metrics")
    st.write("Live hardware network interface statistics from your PC.")

    net_stats = psutil.net_if_stats()
    stats_data = []

    for interface, stat in net_stats.items():
        stats_data.append({
            "Network Interface": interface,
            "Speed (Mbps)": stat.speed,
            "Interface Active": "YES ✅" if stat.isup else "NO ❌",
            "Duplex State": str(stat.duplex)
        })

    st.subheader("Network Cards / Adapters Status")
    st.dataframe(pd.DataFrame(stats_data), use_container_width=True)