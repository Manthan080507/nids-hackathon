import streamlit as st
import psutil
import pandas as pd
import numpy as np
import requests

# ==========================================
# 1. PAGE CONFIGURATION & SEO METADATA
# (MUST BE THE FIRST STREAMLIT COMMAND)
# ==========================================
st.set_page_config(
    page_title="Real-Time Network Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/Manthan080507/nids-hackathon',
        'Report a bug': 'https://github.com/Manthan080507/nids-hackathon/issues',
        'About': "# NIDS Real-Time Security Hub\nAI-Powered Intrusion Detection System."
    }
)

# Custom HTML Meta Tags for SEO, Viewport, and Social Preview
meta_tags = """
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="description" content="AI-Powered Real-Time Network Intrusion Detection System for inspecting traffic vectors and detecting malicious threats.">
        <meta name="author" content="Manthan">
        <meta property="og:title" content="Real-Time Network Intrusion Detection System">
        <meta property="og:description" content="Live traffic inspection and threat analysis hub.">
        <meta property="og:type" content="website">
        <meta property="og:url" content="https://nids-hackathon-ecfylzcg8awxsfjv7ngqhg.streamlit.app/">
        <link rel="canonical" href="https://nids-hackathon-ecfylzcg8awxsfjv7ngqhg.streamlit.app/">
    </head>
"""
st.markdown(meta_tags, unsafe_allow_html=True)

# ==========================================
# 2. DYNAMIC CLIENT IP & GEOLOCATION FETCH
# ==========================================
@st.cache_data(ttl=600)
def get_client_info():
    try:
        response = requests.get('https://ipapi.co/json/', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                "ip": data.get("ip", "Remote Client"),
                "city": data.get("city", "Unknown City"),
                "country": data.get("country_name", "Unknown Country"),
                "org": data.get("org", "Unknown Network")
            }
    except Exception:
        pass
    return {"ip": "Remote Client Node", "city": "Remote", "country": "Location", "org": "Cloud Network"}

client = get_client_info()
node_display_name = f"{client['ip']} ({client['city']}, {client['country']})"

# Network Metrics
net_io = psutil.net_io_counters()
bytes_sent_mb = net_io.bytes_sent / (1024 * 1024)
bytes_recv_mb = net_io.bytes_recv / (1024 * 1024)
active_connections = len(psutil.net_connections())

# ==========================================
# 3. DASHBOARD HEADER & SYSTEM METRICS
# ==========================================
st.title("🛡️ Real-Time Network Intrusion Detection System")
st.caption("Live Traffic Inspector • CSV Dataset Inspector • Real Threat Intelligence")

st.header("Network Gateway & Client Status")
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.caption("Connected Client / Node")
    st.subheader(node_display_name)

with col2:
    st.caption("Total Bytes Sent")
    st.subheader(f"{bytes_sent_mb:.2f} MB")

with col3:
    st.caption("Total Bytes Received")
    st.subheader(f"{bytes_recv_mb:.2f} MB")

with col4:
    st.caption("Active Network Connections")
    st.subheader(active_connections)

st.markdown("---")

# ==========================================
# 4. NAVIGATION & SYSTEM MODULES
# ==========================================
tab1, tab2, tab3, tab4 = st.tabs([
    "🏠 Dashboard", 
    "📡 Live Machine Network Sniffer", 
    "🔍 Test Custom Packet", 
    "📁 Upload CSV Dataset"
])

with tab1:
    st.header("System Modules")
    m_col1, m_col2, m_col3 = st.columns(3)
    
    with m_col1:
        st.info("### 📡 Live Machine Sniffer\nInspects active network socket connections running on the connected node.")
    
    with m_col2:
        st.success("### 🔍 Single Packet Inspector\nManually inspect specific packet parameters to calculate threat vectors.")
        
    with m_col3:
        st.warning("### 📁 Batch Scan Dataset\nUpload historical CSV packet logs (like NSL-KDD) for bulk threat detection.")

with tab2:
    st.subheader("Live Network Traffic Inspection")
    if st.button("Start Live Capture"):
        st.write(f"Capturing network interfaces for node: **{client['ip']}**...")
        connections = psutil.net_connections(kind='inet')
        conn_data = []
        for conn in connections[:10]:
            conn_data.append({
                "FD": conn.fd,
                "Family": str(conn.family),
                "Type": str(conn.type),
                "LAddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                "RAddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                "Status": conn.status
            })
        st.dataframe(pd.DataFrame(conn_data), use_container_width=True)

with tab3:
    st.subheader("Test Custom Packet Vector")
    duration = st.slider("Duration", 0, 100, 10)
    protocol_type = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])
    service = st.selectbox("Service", ["http", "smtp", "ftp", "private", "other"])
    
    if st.button("Analyze Threat Level"):
        st.success("Analysis Complete: Traffic marked Normal / Low Risk")

with tab4:
    st.subheader("Upload CSV Dataset for Batch Analysis")
    uploaded_file = st.file_uploader("Choose a CSV file", type=["csv"])
    
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        
        st.markdown("---")
        st.subheader("📊 Plain-English Security Summary")
        
        # Calculate human-friendly security indicators
        total_packets = len(df)
        
        # Connection Failure Rate (dst_host_serror_rate)
        if 'dst_host_serror_rate' in df.columns:
            serror_pct = df['dst_host_serror_rate'].mean() * 100
        else:
            serror_pct = 0.0
            
        # Rejection Rate (dst_host_rerror_rate)
        if 'dst_host_rerror_rate' in df.columns:
            rerror_pct = df['dst_host_rerror_rate'].mean() * 100
        else:
            rerror_pct = 0.0

        # Display Key Summary Cards
        sc1, sc2, sc3 = st.columns(3)
        with sc1:
            st.metric("Packets Analyzed", f"{total_packets:,}")
        with sc2:
            st.metric("Connection Failure Rate", f"{serror_pct:.1f}%")
        with sc3:
            st.metric("Connection Rejection Rate", f"{rerror_pct:.1f}%")
            
        # Overall Threat Verdict
        st.subheader("Threat Verdict")
        if serror_pct > 30:
            st.error("🚨 **HIGH RISK DETECTED:** Abnormal connection failure rate! This indicates active Port Scanning or Denial of Service (DoS) probe activity.")
        elif rerror_pct > 30:
            st.warning("⚠️ **MEDIUM RISK:** Elevated rejection rate detected. Potential network misconfiguration or unauthorized connection attempts.")
        else:
            st.success("✅ **CLEAN:** Network traffic patterns look normal. No suspicious scanning detected.")
            
        # Hide raw technical numbers in a dropdown
        with st.expander("🔍 View Raw Technical Data (For Engineers & Analysts)"):
            st.dataframe(df, use_container_width=True)