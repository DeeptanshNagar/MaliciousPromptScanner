"""
MAPS Web Dashboard
==================
Streamlit-based dashboard for visualizing scan results and analytics.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

API_BASE_URL = "http://localhost:8000"


def check_api_health():
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except:
        return False


def scan_prompt(prompt: str, detailed: bool = False):
    try:
        response = requests.post(
            f"{API_BASE_URL}/scan_prompt",
            json={"prompt": prompt, "detailed": detailed},
            timeout=30
        )
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        st.error(f"API Error: {e}")
        return None


def get_statistics(hours: int = 24):
    try:
        response = requests.get(f"{API_BASE_URL}/statistics", params={"hours": hours}, timeout=10)
        return response.json() if response.status_code == 200 else None
    except:
        return None


def get_recent_scans(limit: int = 100):
    try:
        response = requests.get(f"{API_BASE_URL}/recent_scans", params={"limit": limit}, timeout=10)
        return response.json() if response.status_code == 200 else None
    except:
        return None


def get_trends(hours: int = 24):
    try:
        response = requests.get(f"{API_BASE_URL}/trends", params={"hours": hours}, timeout=10)
        return response.json() if response.status_code == 200 else None
    except:
        return None


def get_status():
    try:
        response = requests.get(f"{API_BASE_URL}/status", timeout=5)
        return response.json() if response.status_code == 200 else None
    except:
        return None


def render_header():
    st.title("MAPS - Malicious AI Prompt Scanner")
    st.markdown("Multi-layer security engine for detecting malicious prompts")
    st.divider()


def render_scanner():
    st.header("Prompt Scanner")
    
    prompt = st.text_area("Enter prompt to scan:", height=100, placeholder="Type or paste a prompt here...")
    
    col1, col2 = st.columns([1, 4])
    with col1:
        scan_button = st.button("Scan Prompt", type="primary", use_container_width=True)
    with col2:
        detailed = st.checkbox("Show detailed results", value=False)
    
    if scan_button and prompt:
        with st.spinner("Scanning prompt..."):
            result = scan_prompt(prompt, detailed)
        
        if result:
            render_scan_result(result, detailed)


def render_scan_result(result: dict, detailed: bool):
    st.subheader("Scan Result")
    
    decision = result.get('decision', 'UNKNOWN')
    if decision == 'ALLOW':
        st.success(f"Decision: {decision}")
    elif decision == 'WARN':
        st.warning(f"Decision: {decision}")
    else:
        st.error(f"Decision: {decision}")
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Risk Score", f"{result.get('risk_score', 0)}/100")
    with col2:
        st.metric("Classification", result.get('classification', 'UNKNOWN'))
    with col3:
        st.metric("Confidence", f"{result.get('confidence', 0):.2%}")
    with col4:
        st.metric("Scan Time", f"{result.get('scan_time_ms', 0):.1f}ms")
    
    st.info(f"Reason: {result.get('reason', 'N/A')}")
    
    detectors = result.get('detectors_triggered', [])
    if detectors:
        st.write("Detectors Triggered:")
        for detector in detectors:
            st.write(f"  - {detector}")
    
    categories = result.get('categories', [])
    if categories:
        st.write("Categories:", ", ".join(categories))


def render_statistics():
    st.header("Statistics")
    
    hours = st.select_slider("Time Window", options=[1, 6, 12, 24, 48, 72, 168], value=24, format_func=lambda x: f"{x} hours")
    
    stats = get_statistics(hours)
    
    if stats:
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Scans", stats.get('total_scans', 0))
        with col2:
            st.metric("Avg Risk Score", f"{stats.get('average_risk_score', 0):.1f}")
        with col3:
            by_decision = stats.get('by_decision', {})
            st.metric("Blocked", by_decision.get('BLOCK', 0))
        with col4:
            st.metric("Warnings", by_decision.get('WARN', 0))
        
        st.subheader("Classification Breakdown")
        by_classification = stats.get('by_classification', {})
        if by_classification:
            fig = px.pie(
                values=list(by_classification.values()),
                names=list(by_classification.keys()),
                title="Scans by Classification",
                color=list(by_classification.keys()),
                color_discrete_map={'SAFE': '#28a745', 'SUSPICIOUS': '#ffc107', 'MALICIOUS': '#dc3545'}
            )
            st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("Top Detectors Triggered")
        top_detectors = stats.get('top_detectors', {})
        if top_detectors:
            df = pd.DataFrame(list(top_detectors.items()), columns=['Detector', 'Count']).head(10)
            fig = px.bar(df, x='Detector', y='Count', title="Most Triggered Detectors")
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No statistics available. Start scanning prompts to see data.")


def render_trends():
    st.header("Trends")
    
    hours = st.select_slider("Trend Time Window", options=[6, 12, 24, 48, 72], value=24, format_func=lambda x: f"{x} hours", key="trend_hours")
    
    trends_data = get_trends(hours)
    
    if trends_data and trends_data.get('trends'):
        df = pd.DataFrame(trends_data['trends'])
        
        for col in ['SAFE', 'SUSPICIOUS', 'MALICIOUS']:
            if col not in df.columns:
                df[col] = 0
        
        fig = go.Figure()
        
        if 'SAFE' in df.columns:
            fig.add_trace(go.Scatter(x=df['hour'], y=df['SAFE'], name='SAFE', line=dict(color='#28a745'), fill='tonexty'))
        if 'SUSPICIOUS' in df.columns:
            fig.add_trace(go.Scatter(x=df['hour'], y=df['SUSPICIOUS'], name='SUSPICIOUS', line=dict(color='#ffc107'), fill='tonexty'))
        if 'MALICIOUS' in df.columns:
            fig.add_trace(go.Scatter(x=df['hour'], y=df['MALICIOUS'], name='MALICIOUS', line=dict(color='#dc3545'), fill='tonexty'))
        
        fig.update_layout(title="Scan Trends Over Time", xaxis_title="Hour", yaxis_title="Number of Scans", hovermode='x unified')
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No trend data available yet.")


def render_recent_scans():
    st.header("Recent Scans")
    
    scans_data = get_recent_scans(limit=50)
    
    if scans_data and scans_data.get('logs'):
        logs = scans_data['logs']
        df = pd.DataFrame(logs)
        
        display_cols = ['timestamp', 'prompt', 'classification', 'risk_score', 'decision']
        available_cols = [c for c in display_cols if c in df.columns]
        df_display = df[available_cols].copy()
        
        if 'prompt' in df_display.columns:
            df_display['prompt'] = df_display['prompt'].str[:80] + '...'
        
        st.dataframe(df_display, use_container_width=True, hide_index=True)
    else:
        st.info("No recent scans available.")


def render_status():
    st.header("System Status")
    
    status = get_status()
    
    if status:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Layer Status")
            enabled_layers = status.get('enabled_layers', {})
            for layer, enabled in enabled_layers.items():
                if enabled:
                    st.success(f"{layer}")
                else:
                    st.error(f"{layer}")
        
        with col2:
            st.subheader("Model Information")
            st.write(f"ML Model Type: {status.get('ml_model_type', 'N/A')}")
            st.write(f"ML Trained: {'Yes' if status.get('ml_trained') else 'No'}")
            st.write(f"Keywords: {status.get('num_keywords', 0)}")
            st.write(f"Regex Patterns: {status.get('num_regex_patterns', 0)}")
            st.write(f"N-gram Templates: {status.get('num_ngram_templates', 0)}")
            st.write(f"Semantic Examples: {status.get('num_semantic_examples', 0)}")
        
        st.subheader("Risk Thresholds")
        thresholds = status.get('risk_thresholds', {})
        st.write(f"Safe: 0-{thresholds.get('safe_max', 30)}")
        st.write(f"Suspicious: {thresholds.get('safe_max', 30)+1}-{thresholds.get('suspicious_max', 60)}")
        st.write(f"Malicious: {thresholds.get('suspicious_max', 60)+1}-100")
    else:
        st.error("Unable to fetch system status. Is the API running?")


def main():
    st.set_page_config(page_title="MAPS Dashboard", page_icon="", layout="wide", initial_sidebar_state="expanded")
    
    st.sidebar.title("MAPS")
    st.sidebar.markdown("Malicious AI Prompt Scanner")
    st.sidebar.divider()
    
    page = st.sidebar.radio("Navigation", ["Scanner", "Statistics", "Trends", "Recent Scans", "System Status"])
    
    if not check_api_health():
        st.sidebar.error("API Offline")
        st.sidebar.info("Start the API with: python -m backend.api.main")
    else:
        st.sidebar.success("API Online")
    
    render_header()
    
    if page == "Scanner":
        render_scanner()
    elif page == "Statistics":
        render_statistics()
    elif page == "Trends":
        render_trends()
    elif page == "Recent Scans":
        render_recent_scans()
    elif page == "System Status":
        render_status()
    
    st.sidebar.divider()
    st.sidebar.caption("MAPS v1.0.0 - AI Security")


if __name__ == "__main__":
    main()
