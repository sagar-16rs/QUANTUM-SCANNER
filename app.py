import streamlit as st
import pandas as pd
import json
import plotly.express as px
from scanner import bulk_scan, enterprise_score

# ⚙️ Page Configuration
st.set_page_config(page_title="PNB Quantum Scanner", page_icon="🛡️", layout="wide")

# 🎨 Custom CSS for Enterprise UI
st.markdown("""
    <style>
    .metric-card { background-color: #1a1a24; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #333;}
    .metric-title { font-size: 14px; color: #888; text-transform: uppercase; letter-spacing: 1px;}
    .metric-value { font-size: 32px; font-weight: bold; color: #fff; margin: 10px 0;}
    .grade-A { color: #00ff88; font-size: 20px; font-weight: bold; }
    .grade-B { color: #00ccff; font-size: 20px; font-weight: bold; }
    .grade-C { color: #ffcc00; font-size: 20px; font-weight: bold; }
    .grade-F { color: #ff3333; font-size: 20px; font-weight: bold; }
    </style>
""", unsafe_allow_html=True)

# 🗺️ Sidebar Navigation
st.sidebar.image("https://upload.wikimedia.org/wikipedia/commons/thumb/c/c3/Punjab_National_Bank_Logo.svg/1024px-Punjab_National_Bank_Logo.svg.png", width=160)
st.sidebar.markdown("### 🛡️ DevSecOps Console")
menu = st.sidebar.radio("Navigation", ["🏠 Executive Dashboard", "🔍 Deep Analysis Scanner", "📄 CBOM Export"])
st.sidebar.caption("v2.1.0 | Enterprise Edition")

# ---------------------------------------------------------
# 🏠 EXECUTIVE DASHBOARD
# ---------------------------------------------------------
if menu == "🏠 Executive Dashboard":
    st.title("Enterprise Cryptographic Posture")
    st.caption("Live global visibility into the organization's Quantum Vulnerability Index (QVI).")
    
    # 1. Top Metrics View
    c1, c2, c3, c4 = st.columns(4)
    c1.markdown('<div class="metric-card"><div class="metric-title">Total Monitored Assets</div><div class="metric-value">128</div></div>', unsafe_allow_html=True)
    c2.markdown('<div class="metric-card"><div class="metric-title">Global QVI Score</div><div class="metric-value" style="color:#00ccff;">820</div></div>', unsafe_allow_html=True)
    c3.markdown('<div class="metric-card"><div class="metric-title">High Risk (Grade F)</div><div class="metric-value" style="color:#ff3333;">14</div></div>', unsafe_allow_html=True)
    c4.markdown('<div class="metric-card"><div class="metric-title">Expiring Certificates</div><div class="metric-value" style="color:#ffcc00;">9</div></div>', unsafe_allow_html=True)
    
    st.write("---")
    
    # 2. Interactive Charts
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("📊 Asset Risk Distribution")
        fig1 = px.pie(values=[45, 30, 15, 10], names=["Tier-1 Elite", "Tier-2 Standard", "Tier-3 Legacy", "Critical Risk"], hole=0.5, 
                      color_discrete_sequence=["#00ff88", "#00ccff", "#ffcc00", "#ff3333"])
        fig1.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", margin=dict(t=0, b=0, l=0, r=0))
        st.plotly_chart(fig1, use_container_width=True)
        
    with col2:
        st.subheader("⏳ Quantum Vulnerability Timeline")
        fig2 = px.bar(x=["0-1 Yr", "1-3 Yrs", "3-5 Yrs", "5+ Yrs (PQC)"], y=[12, 45, 60, 11], 
                      labels={'x': 'Time to Vulnerability', 'y': 'Number of Assets'},
                      color_discrete_sequence=["#00ccff"])
        fig2.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", margin=dict(t=0, b=0, l=0, r=0))
        st.plotly_chart(fig2, use_container_width=True)

    # 3. The Ultimate Feature: Attack Surface Treemap
    st.write("---")
    st.subheader("🌐 Quantum Attack Surface Map")
    st.caption("Interactive drill-down of the cryptographic blast radius. Click to zoom into Risk Tiers and Protocols.")
    
    # Check if a scan has been run, otherwise use dynamic enterprise placeholder data
    if 'results' in st.session_state and st.session_state['results']:
        tree_df = pd.DataFrame([r for r in st.session_state['results'] if r.get("status") == "Success"])
    else:
        tree_df = pd.DataFrame([
            {"endpoint": "pq.cloudflareresearch.com", "tier": "Tier-1 Elite", "protocol": "TLSv1.3", "score": 1000},
            {"endpoint": "auth.pnbindia.in", "tier": "Tier-1 Elite", "protocol": "TLSv1.3", "score": 950},
            {"endpoint": "google.com", "tier": "Tier-2 Standard", "protocol": "TLSv1.3", "score": 850},
            {"endpoint": "api.pnbindia.in", "tier": "Tier-3 Legacy", "protocol": "TLSv1.2", "score": 600},
            {"endpoint": "dev.internal.net", "tier": "Critical Risk", "protocol": "TLSv1.1", "score": 300},
            {"endpoint": "expired.badssl.com", "tier": "Critical Risk", "protocol": "TLSv1.0", "score": 100}
        ])

    if not tree_df.empty and "tier" in tree_df.columns:
        fig_tree = px.treemap(
            tree_df,
            path=['tier', 'protocol', 'endpoint'],
            color='score',
            color_continuous_scale='RdYlGn', 
            range_color=[0, 1000]
        )
        fig_tree.update_layout(margin=dict(t=10, l=10, r=10, b=10), paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig_tree, use_container_width=True)

# ---------------------------------------------------------
# 🔍 DEEP ANALYSIS SCANNER
# ---------------------------------------------------------
elif menu == "🔍 Deep Analysis Scanner":
    st.title("🛡️ Deep Asset Discovery & QVI Engine")
    st.caption("Executes multi-threaded TLS extraction, ALPN detection, and Quantum Vulnerability Indexing (QVI).")
    
    col1, col2 = st.columns([2, 1])
    with col1:
        targets_text = st.text_area("Scope (Domains, IPs, /24 CIDR)", "pq.cloudflareresearch.com\ngoogle.com\nexpired.badssl.com", height=110)
    with col2:
        deep_scan = st.checkbox("🔍 Enable Shadow IT Discovery", help="Hunts for hidden api/dev domains via SANs extraction.")
        scan_button = st.button("🚀 Execute Deep Scan", type="primary", use_container_width=True)
    
    if scan_button:
        targets = [t.strip() for t in targets_text.split("\n") if t.strip()]
        with st.spinner("Executing asynchronous socket connections and calculating QVI..."):
            st.session_state['results'] = bulk_scan(targets, deep_scan=deep_scan)
            
    if 'results' in st.session_state:
        results = st.session_state['results']
        ent_score = enterprise_score(results)
        
        st.write("---")
        st.markdown(f"### 🌐 Live Global QVI Score: `{ent_score} / 1000`")
        st.progress(ent_score / 1000)
        st.write("---")
        
        st.subheader("Asset Analysis & Automated Playbooks")
        
        for r in results:
            if r.get("status") == "Failed":
                st.error(f"❌ {r['endpoint']} | Connection Failed: {r.get('error')}")
                continue

            grade_class = f"grade-{r['grade'][0]}" if '+' not in r['grade'] else "grade-A"
            icon = "✅" if "A" in r['grade'] else "⚠️" if "B" in r['grade'] or "C" in r['grade'] else "🚨"
            
            with st.expander(f"{icon} Endpoint: {r['endpoint']} | Grade: {r['grade']} | Score: {r['score']}/1000"):
                
                c1, c2, c3 = st.columns(3)
                with c1:
                    st.markdown("**💻 Server Intelligence**")
                    st.write(f"**Protocol:** `{r.get('protocol', 'N/A')}`")
                    st.write(f"**ALPN (HTTP/2):** `{r.get('alpn', 'None')}`")
                    st.write(f"**HSTS Enforced:** {'✅ Yes' if r.get('hsts_enabled') else '❌ No'}")
                    if r['certificate'].get('sans'):
                        st.caption(f"**Shadow Aliases (SANs):** {', '.join(r['certificate']['sans'])}")
                        
                with c2:
                    st.markdown("**🔐 Cryptographic Posture**")
                    st.write(f"**Cipher Suite:** `{r.get('cipher', 'N/A')}`")
                    st.write(f"**Public Key:** `{r['certificate'].get('key_algorithm')} ({r['certificate'].get('key_size')}-bit)`")
                    st.write(f"**Cert Expiry:** `{r.get('cert_valid_until', 'N/A')}`")
                    st.markdown(f"**PQC Status:** {r.get('pqc_label')}")
                    
                with c3:
                    st.markdown("**⚙️ Automated Playbook**")
                    st.markdown(f"<span class='{grade_class}'>Grade: {r['grade']} ({r['tier']})</span>", unsafe_allow_html=True)
                    
                    if r['vulnerabilities']:
                        for v in r['vulnerabilities']:
                            st.error(f"• {v}")
                    if r['recommendations']:
                        for rec in r['recommendations']:
                            st.warning(f"• {rec}")
                    if not r['vulnerabilities'] and not r['recommendations']:
                        st.success("✅ Configuration meets optimal NIST security standards.")

# ---------------------------------------------------------
# 📄 CBOM EXPORT
# ---------------------------------------------------------
elif menu == "📄 CBOM Export":
    st.title("CERT-In Compliant Data Export")
    st.caption("Generate machine-readable Cryptographic Bill of Materials (CBOM) for auditing.")
    
    if 'results' in st.session_state:
        valid_results = [r for r in st.session_state['results'] if r.get("status") == "Success"]
        if valid_results:
            col1, col2 = st.columns(2)
            with col1:
                st.download_button("📥 Export JSON (SIEM format)", data=json.dumps(valid_results, indent=4), file_name="qvi_cbom.json", mime="application/json", use_container_width=True)
            with col2:
                df = pd.DataFrame(valid_results)
                # Clean lists for CSV
                df['vulnerabilities'] = df['vulnerabilities'].apply(lambda x: '; '.join(x) if isinstance(x, list) else x)
                df['recommendations'] = df['recommendations'].apply(lambda x: '; '.join(x) if isinstance(x, list) else x)
                csv = df.to_csv(index=False).encode('utf-8')
                st.download_button("📥 Export CSV (Auditor format)", data=csv, file_name="qvi_audit_cbom.csv", mime="text/csv", type="primary", use_container_width=True)
            
            st.write("---")
            st.subheader("Preview Export Data")
            st.dataframe(df[['endpoint', 'score', 'tier', 'protocol', 'pqc_label']], use_container_width=True)
        else:
            st.warning("No successful scan data to export.")
    else:
        st.info("⚠️ Please run a deep scan first to populate the CBOM database.")