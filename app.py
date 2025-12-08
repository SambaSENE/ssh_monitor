import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
# CONFIG DE LA PAGE
# ═══════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="MonitorSSH",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Thème personnalisé
st.markdown("""
    <style>
    .main {
        padding-top: 2rem;
    }
    .header-main {
        background: linear-gradient(135deg, #0f0f1e 0%, #1a1a3a 100%);
        border-left: 5px solid #00ff88;
        padding: 30px;
        border-radius: 10px;
        color: #00ff88;
        margin-bottom: 30px;
        box-shadow: 0 0 20px rgba(0, 255, 136, 0.2);
    }
    .header-main h1 {
        color: #00ff88;
        text-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
    }
    .header-main p {
        color: #00ff88;
    }
    .section-title {
        font-size: 24px;
        font-weight: bold;
        margin-top: 30px;
        margin-bottom: 20px;
        border-left: 5px solid #00ff88;
        padding-left: 15px;
        color: #00ff88;
        text-shadow: 0 0 5px rgba(0, 255, 136, 0.3);
    }
    .metric-card {
        background: linear-gradient(135deg, #0f0f1e 0%, #1a1a3a 100%);
        border: 2px solid #00ff88;
        padding: 20px;
        border-radius: 8px;
        color: #00ff88;
        box-shadow: 0 0 15px rgba(0, 255, 136, 0.15);
    }
    </style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# HEADER PERSONNALISÉ
# ═══════════════════════════════════════════════════════════════
st.markdown("""
    <div class="header-main">
        <h1>🛡️ MonitorSSH - Dashboard de Surveillance SSH</h1>
        <p style="font-size: 16px; margin-top: 10px;">
            Analysez les tentatives de connexion SSH et identifiez les menaces en temps réel
        </p>
    </div>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# CHARGEMENT DES DONNÉES AVEC CACHE
# ═══════════════════════════════════════════════════════════════
@st.cache_data
def load_data():
    df = pd.read_csv("dataset_ssh.csv")
    return df

df = load_data()

# ═══════════════════════════════════════════════════════════════
# SIDEBAR - FILTRES
# ═══════════════════════════════════════════════════════════════
st.sidebar.markdown("### 🔍 Filtres et Paramètres")
st.sidebar.markdown("---")

# Filtre EventId
event_ids = sorted(df["EventId"].dropna().astype(str).unique().tolist())
event_choice = st.sidebar.selectbox(
    "📋 Type d'événement (EventId)",
    ["Tous"] + event_ids,
    help="Sélectionnez un type d'événement spécifique ou tous les événements"
)

# Filtre SourceIP
ip_options = sorted(df["SourceIP"].dropna().astype(str).unique().tolist())
ip_choices = st.sidebar.multiselect(
    "🔗 Adresses IP à afficher",
    ip_options,
    default=ip_options,
    help="Sélectionnez les IPs que vous voulez analyser"
)

# Message de validation des filtres
if not ip_choices:
    st.sidebar.warning("⚠️ Aucune IP sélectionnée")

st.sidebar.markdown("---")
st.sidebar.markdown("""
    **💡 Conseils d'utilisation:**
    - Utilisez les filtres pour affiner votre analyse
    - Les métriques se mettent à jour automatiquement
    - Explorez les données filtrées ci-dessous
""")

# ═══════════════════════════════════════════════════════════════
# APPLICATION DES FILTRES
# ═══════════════════════════════════════════════════════════════
df_filtered = df.copy()

if event_choice != "Tous":
    df_filtered = df_filtered[df_filtered["EventId"].astype(str) == event_choice]

if ip_choices:
    df_filtered = df_filtered[df_filtered["SourceIP"].astype(str).isin(ip_choices)]

# ═══════════════════════════════════════════════════════════════
# VÉRIFICATION DES RÉSULTATS FILTRÉS
# ═══════════════════════════════════════════════════════════════
if len(df_filtered) == 0:
    st.warning("⚠️ Aucune donnée ne correspond à vos filtres. Essayez de modifier les sélections.")
    st.stop()

# ═══════════════════════════════════════════════════════════════
# MÉTRIQUES CLÉS
# ═══════════════════════════════════════════════════════════════
st.markdown('<div class="section-title">📊 Métriques Principales</div>', unsafe_allow_html=True)

col1, col2, col3, col4 = st.columns(4)

with col1:
    total_events = len(df_filtered)
    st.metric(
        label="📈 Total Événements",
        value=f"{total_events:,}",
        help="Nombre total d'événements correspondant aux filtres"
    )

with col2:
    unique_ips = df_filtered["SourceIP"].nunique()
    st.metric(
        label="🌐 IPs Uniques",
        value=f"{unique_ips}",
        help="Nombre d'adresses IP différentes"
    )

with col3:
    if len(df_filtered) > 0:
        freq = len(df_filtered) / unique_ips if unique_ips > 0 else 0
        st.metric(
            label="📊 Tentatives/IP",
            value=f"{freq:.1f}",
            help="Moyenne de tentatives par IP"
        )

with col4:
    unique_events = df_filtered["EventId"].nunique()
    st.metric(
        label="🎯 Types d'Événements",
        value=f"{unique_events}",
        help="Nombre de types d'événements différents"
    )

# ═══════════════════════════════════════════════════════════════
# TOP 5 IPS AGRESSIVES
# ═══════════════════════════════════════════════════════════════
st.markdown('<div class="section-title">Top 5 Adresses IP les Plus Agressives</div>', unsafe_allow_html=True)

col_chart1, col_chart2 = st.columns([2, 1])

with col_chart1:
    top_ips = df_filtered["SourceIP"].value_counts().head(5)
    
    # Créer un graphique personnalisé avec Matplotlib
    fig, ax = plt.subplots(figsize=(10, 5))
    colors = ['#667eea', '#764ba2', '#f093fb', '#4facfe', '#00f2fe']
    top_ips.plot(kind='barh', ax=ax, color=colors)
    ax.set_xlabel('Nombre de tentatives', fontsize=12, fontweight='bold')
    ax.set_ylabel('Adresse IP', fontsize=12, fontweight='bold')
    ax.set_title('Tentatives par IP', fontsize=14, fontweight='bold', pad=20)
    ax.invert_yaxis()
    plt.tight_layout()
    st.pyplot(fig)

with col_chart2:
    st.markdown("**Statistiques Top 5:**")
    for i, (ip, count) in enumerate(top_ips.items(), 1):
        st.write(f"**{i}. {ip}**")
        st.write(f"   {count} tentatives")
        progress = min(count / top_ips.iloc[0] * 100, 100) if len(top_ips) > 0 else 0
        st.progress(int(progress) / 100)

# ═══════════════════════════════════════════════════════════════
# DISTRIBUTION PAR TYPE D'ÉVÉNEMENT
# ═══════════════════════════════════════════════════════════════
st.markdown('<div class="section-title">📋 Distribution par Type d\'Événement</div>', unsafe_allow_html=True)

event_dist = df_filtered["EventId"].value_counts()

col_event1, col_event2 = st.columns(2)

with col_event1:
    fig, ax = plt.subplots(figsize=(10, 5))
    event_dist.plot(kind='bar', ax=ax, color=['#667eea', '#764ba2', '#f093fb', '#4facfe'][:len(event_dist)])
    ax.set_xlabel('Type d\'Événement', fontsize=12, fontweight='bold')
    ax.set_ylabel('Nombre d\'occurrences', fontsize=12, fontweight='bold')
    ax.set_title('Événements par Type', fontsize=14, fontweight='bold', pad=20)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    st.pyplot(fig)

with col_event2:
    st.markdown("**Répartition:**")
    for event, count in event_dist.items():
        percentage = (count / len(df_filtered)) * 100
        st.write(f"**{event}:** {count} ({percentage:.1f}%)")

# ═══════════════════════════════════════════════════════════════
# DONNÉES FILTRÉES DÉTAILLÉES
# ═══════════════════════════════════════════════════════════════
st.markdown('<div class="section-title">🔍 Données Détaillées (Filtrées)</div>', unsafe_allow_html=True)

col_data1, col_data2 = st.columns([3, 1])

with col_data1:
    st.dataframe(
        df_filtered,
        width='stretch',
        height=400
    )

with col_data2:
    st.markdown("**Informations:**")
    st.write(f"📌 Lignes affichées: {len(df_filtered)}")
    st.write(f"📊 Colonnes: {len(df_filtered.columns)}")
    st.markdown("---")
    st.markdown("**Actions:**")
    if st.button("📥 Télécharger les données"):
        csv = df_filtered.to_csv(index=False)
        st.download_button(
            label="Télécharger CSV",
            data=csv,
            file_name="ssh_logs_filtered.csv",
            mime="text/csv"
        )

# ═══════════════════════════════════════════════════════════════
# FOOTER
# ═══════════════════════════════════════════════════════════════
st.markdown("---")
st.markdown("""
    <div style="text-align: center; padding: 20px; color: #666;">
        <p><strong>MonitorSSH Dashboard</strong> | Analyseur de logs SSH en temps réel</p>
        <p style="font-size: 12px;">Données mises à jour avec cache intelligent pour optimiser les performances</p>
    </div>
""", unsafe_allow_html=True)