import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

# ═══════════════════════════════════════════════════════════════
# 1) CONFIGURATION DE LA PAGE STREAMLIT
# ═══════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="MonitorSSH",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════════
# 2) STYLES CSS GLOBAUX (THEME DARK SOC)
# ═══════════════════════════════════════════════════════════════
CUSTOM_CSS = """
<style>
.header-main {
    background: linear-gradient(135deg, #0f0f1e 0%, #1a1a3a 100%);
    border-left: 5px solid #00ff88;
    padding: 24px 30px;
    border-radius: 10px;
    margin-bottom: 30px;
    color: #00ff88;
    box-shadow: 0 0 20px rgba(0, 255, 136, 0.2);
}
.header-main h1 { margin: 0; }
.header-main p { margin: 4px 0 0 0; color: #cbd5f5; }

.section-title {
    font-size: 20px;
    font-weight: 700;
    margin-top: 25px;
    margin-bottom: 15px;
    border-left: 4px solid #00ff88;
    padding-left: 10px;
    color: #00ff88;
}

/* Badges de statut global (vue SOC) */
.status-badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    margin-left: 10px;
}
.status-ok   { background: #1f3b2f; color: #34d399; border: 1px solid #34d399; }
.status-warn { background: #423225; color: #fbbf24; border: 1px solid #fbbf24; }
.status-crit { background: #451b1b; color: #f87171; border: 1px solid #f87171; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# 3) HEADER PRINCIPAL
# ═══════════════════════════════════════════════════════════════
st.markdown(
    """
    <div class="header-main">
        <h1>🛡️ MonitorSSH</h1>
        <p>Vue SOC : activité SSH, IP agressives, événements critiques et chronologie des attaques</p>
    </div>
    """,
    unsafe_allow_html=True,
)


# ═══════════════════════════════════════════════════════════════
# 4) CHARGEMENT + VALIDATION DU DATASET AVEC CACHE
# ═══════════════════════════════════════════════════════════════
@st.cache_data
def load_dataset(file):
    """Charge le CSV, nettoie les colonnes et convertit Timestamp si présent."""
    try:
        df = pd.read_csv(file)
        df.columns = df.columns.str.strip()

        # Colonnes minimales requises
        if "SourceIP" not in df.columns or "EventId" not in df.columns:
            return None, "Colonnes obligatoires manquantes : SourceIP ou EventId"

        # Conversion Timestamp → datetime si la colonne existe
        if "Timestamp" in df.columns:
            try:
                df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
            except Exception:
                pass

        return df, None
    except Exception as e:
        return None, str(e)


# ═══════════════════════════════════════════════════════════════
# 5) SIDEBAR - CHARGEMENT DU FICHIER CSV
# ═══════════════════════════════════════════════════════════════
st.sidebar.markdown("### 📥 Données")
uploaded_file = st.sidebar.file_uploader("Importer un CSV SSH", type=["csv"])

if uploaded_file:
    df, error = load_dataset(uploaded_file)
else:
    df, error = load_dataset("dataset_ssh.csv")

if error:
    st.error(f"❌ Erreur chargement : {error}")
    st.stop()

# ═══════════════════════════════════════════════════════════════
# 6) SIDEBAR - FILTRES PRINCIPAUX
# ═══════════════════════════════════════════════════════════════
st.sidebar.markdown("---")

# Selectbox EventId (TU DOIS LE VOIR DANS LA SIDEBAR)
st.sidebar.markdown("### 🎛️ Filtres")
event_list = sorted(df["EventId"].astype(str).unique())
event_choice = st.sidebar.selectbox(
    "Type d'événement",
    ["Tous"] + event_list,
    help="Filtrer par type d'événement (EventId).",
)

# Multiselect IP
ip_list = sorted(df["SourceIP"].dropna().astype(str).unique())
ip_choices = st.sidebar.multiselect(
    "Adresses IP",
    ip_list,
    default=ip_list,
    help="Limiter l’analyse à certaines adresses IP.",
)

# ═══════════════════════════════════════════════════════════════
# 7) APPLICATION DES FILTRES
# ═══════════════════════════════════════════════════════════════
df_filtered = df.copy()

if event_choice != "Tous":
    df_filtered = df_filtered[df_filtered["EventId"].astype(str) == event_choice]

df_filtered = df_filtered[df_filtered["SourceIP"].astype(str).isin(ip_choices)]

# Résumé rapide des filtres
st.sidebar.markdown("---")
st.sidebar.caption(
    f"Événements filtrés : {len(df_filtered)}\n"
    f"IPs actives : {df_filtered['SourceIP'].nunique()}"
)

# Si plus de données après filtrage
if df_filtered.empty:
    st.warning("⚠️ Aucun résultat avec les filtres actuels.")
    st.stop()

# ═══════════════════════════════════════════════════════════════
# 8) STATUT GLOBAL & MÉTRIQUES
# ═══════════════════════════════════════════════════════════════
st.markdown('<div class="section-title">📊 Vue globale</div>', unsafe_allow_html=True)

total_events = len(df_filtered)
unique_ips = df_filtered["SourceIP"].nunique()

# EventId considérés comme critiques (exemple : 4625)
critical_ids = ["4625"]  # adapte selon ton dataset
crit_count = df_filtered[df_filtered["EventId"].astype(str).isin(critical_ids)].shape[0]

# Statut simple basé sur le nombre d'événements critiques
if crit_count == 0:
    status_class = "status-ok"
    status_label = "Activité normale"
elif crit_count < 50:
    status_class = "status-warn"
    status_label = "Attention : activité élevée"
else:
    status_class = "status-crit"
    status_label = "Critique : nombreuses attaques"

st.markdown(
    f"""
    <p>
        Statut global :
        <span class="status-badge {status_class}">{status_label}</span>
    </p>
    """,
    unsafe_allow_html=True,
)

col1, col2, col3 = st.columns(3)
with col1:
    st.metric("📈 Total événements", total_events)
with col2:
    st.metric("🌐 IPs uniques", unique_ips)
with col3:
    ip_avg = total_events / max(unique_ips, 1)
    st.metric("📊 Tentatives / IP", f"{ip_avg:.1f}")

# Marquage des lignes critiques
df_filtered["Critique"] = df_filtered["EventId"].astype(str).isin(critical_ids)

# ═══════════════════════════════════════════════════════════════
# 9) IP AGRESSIVES & ÉVÉNEMENTS CRITIQUES
# ═══════════════════════════════════════════════════════════════
st.markdown(
    '<div class="section-title">🚨 IP et événements critiques</div>',
    unsafe_allow_html=True,
)
col_crit_left, col_crit_right = st.columns([2, 1])

with col_crit_left:
    st.markdown("**Top 5 IP agressives (tous événements)**")
    top_ips = df_filtered["SourceIP"].value_counts().head(5)

    fig, ax = plt.subplots(figsize=(8, 4))
    top_ips.plot(
        kind="barh",
        color=["#00ff88", "#4facfe", "#764ba2", "#f093fb", "#9580ff"],
        ax=ax,
    )
    ax.set_xlabel("Tentatives")
    ax.set_ylabel("Adresse IP")
    ax.invert_yaxis()
    plt.tight_layout()
    st.pyplot(fig)

with col_crit_right:
    st.markdown("**Top IP - événements critiques**")
    top_critical_ips = (
        df_filtered[df_filtered["Critique"]]["SourceIP"].value_counts().head(5)
    )

    if top_critical_ips.empty:
        st.info("Aucun événement critique détecté avec les filtres actuels.")
    else:
        fig, ax = plt.subplots(figsize=(6, 4))
        top_critical_ips.plot(kind="barh", ax=ax, color="#ff4b4b")
        ax.set_xlabel("Événements critiques")
        ax.set_ylabel("Adresse IP")
        ax.invert_yaxis()
        plt.tight_layout()
        st.pyplot(fig)

# Répartition par EventId
st.markdown(
    '<div class="section-title">📋 Répartition des EventId</div>',
    unsafe_allow_html=True,
)
event_dist = df_filtered["EventId"].value_counts()

fig, ax = plt.subplots(figsize=(10, 3))
event_dist.plot(kind="bar", ax=ax, color="#00ff88")
ax.set_xlabel("EventId")
ax.set_ylabel("Occurrences")
plt.xticks(rotation=45)
plt.tight_layout()
st.pyplot(fig)

# ═══════════════════════════════════════════════════════════════
# 10) CHRONOLOGIE DES ATTAQUES
# ═══════════════════════════════════════════════════════════════
if "Timestamp" in df_filtered.columns:
    st.markdown(
        '<div class="section-title">📆 Chronologie des attaques</div>',
        unsafe_allow_html=True,
    )

    df_ts = df_filtered.dropna(subset=["Timestamp"]).copy()

    # Attaques totales par jour
    attacks_per_day = (
        df_ts.groupby(df_ts["Timestamp"].dt.floor("d"))
        .size()
        .reset_index(name="Attaques")
        .sort_values("Timestamp")
    )

    fig, ax = plt.subplots(figsize=(10, 3))
    ax.plot(
        attacks_per_day["Timestamp"],
        attacks_per_day["Attaques"],
        color="#00ff88",
        marker="o",
    )
    ax.set_xlabel("Date")
    ax.set_ylabel("Nombre d'attaques")
    ax.grid(alpha=0.2)
    plt.xticks(rotation=45)
    plt.tight_layout()
    st.pyplot(fig)

    # Attaques critiques par jour
    crit_ts = df_ts[df_ts["Critique"]]
    if not crit_ts.empty:
        crit_per_day = (
            crit_ts.groupby(crit_ts["Timestamp"].dt.floor("d"))
            .size()
            .reset_index(name="Attaques critiques")
            .sort_values("Timestamp")
        )

        fig, ax = plt.subplots(figsize=(10, 3))
        ax.plot(
            crit_per_day["Timestamp"],
            crit_per_day["Attaques critiques"],
            color="#ff4b4b",
            marker="o",
        )
        ax.set_xlabel("Date")
        ax.set_ylabel("Nb attaques critiques")
        ax.grid(alpha=0.2)
        plt.xticks(rotation=45)
        plt.tight_layout()
        st.pyplot(fig)

# ═══════════════════════════════════════════════════════════════
# 11) DONNÉES BRUTES & EXPORT
# ═══════════════════════════════════════════════════════════════
st.markdown(
    '<div class="section-title">🔍 Données filtrées</div>', unsafe_allow_html=True
)
st.dataframe(df_filtered, use_container_width=True)

st.download_button(
    "📥 Télécharger le CSV filtré",
    df_filtered.to_csv(index=False),
    "ssh_logs_filtered.csv",
)

# ═══════════════════════════════════════════════════════════════
# 12) FOOTER
# ═══════════════════════════════════════════════════════════════
st.markdown("---")
st.markdown(
    "<center>🛡️ MonitorSSH — Vue SOC SSH (IPs, événements critiques, chronologie)</center>",
    unsafe_allow_html=True,
)
