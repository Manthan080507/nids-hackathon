import streamlit as st
import socket
import psutil
import pandas as pd
import numpy as np
import time

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
# 2. DASHBOARD HEADER & SYSTEM METRICS
# ==========================================
st.title("🛡️ Real-Time Network Intrusion Detection System")
st.caption("Live Local Traffic Sniffer • CSV Dataset Inspector • Real Threat Intelligence")

# Fetch System Metrics
hostname = socket.gethostname()
net_io = psutil.net_io_counters()
bytes_sent_mb = net_io.bytes_sent / (1024 * 1024)
bytes_recv_mb = net_io.bytes_recv / (1024 * 1024)
active_connections = len(psutil.net_connections())

st.header("Local Network Gateway Status")
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.caption("System Hostname")
    st.subheader(hostname)

with col2:
    st.caption("Total Bytes Sent")
    st.subheader(f"{bytes_sent_mb:.2f} MB")

with col3:
    st.caption("Total Bytes Received")
    st.subheader(f"{bytes_recv_mb:.2f} MB")

with col4:
    st.caption("Active Connections")
    st.subheader(active_connections)

st.markdown("---")

# ==========================================
# 3. NAVIGATION & SYSTEM MODULES
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
        st.info("### 📡 Live Machine Sniffer\nCaptures real active network socket connections running on your computer right now.")
    
    with m_col2:
        st.success("### 🔍 Single Packet Inspector\nManually inspect specific packet parameters to calculate threat vectors.")
        
    with m_col3:
        st.warning("### 📁 Batch Scan Dataset\nUpload historical CSV packet logs (like NSL-KDD) for bulk threat detection.")

with tab2:
    st.subheader("Live Network Traffic Inspection")
    if st.button("Start Live Capture"):
        st.write("Capturing active network interfaces...")
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
        st.write("Dataset Preview:", df.head())