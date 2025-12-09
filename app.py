import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

# ── CONFIG ─────────────────────────────────────────────────────
st.set_page_config(
    page_title="MonitorSSH",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── HEADER ─────────────────────────────────────────────────────
col_header1, col_header2 = st.columns([3, 1])
with col_header1:
    st.markdown("## 🛡️ MonitorSSH")
    st.markdown(
        "Surveillance des événements SSH : IP agressives, utilisateurs, types d'événements et carte des IP."
    )
with col_header2:
    st.markdown("### 📡 Mode SOC")
    st.caption("Vue analytique des tentatives de connexion SSH.")

st.markdown("---")

# ── DATA ───────────────────────────────────────────────────────
@st.cache_data
def load_dataset(file):
    try:
        df = pd.read_csv(file)
        df.columns = df.columns.str.strip()
        if "SourceIP" not in df.columns or "EventId" not in df.columns:
            return None, "Colonnes obligatoires manquantes : SourceIP ou EventId"
        if "Timestamp" in df.columns:
            df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
        return df, None
    except Exception as e:
        return None, str(e)

st.sidebar.header("📥 Données")
uploaded_file = st.sidebar.file_uploader("Importer un CSV SSH", type=["csv"])

if uploaded_file:
    df, error = load_dataset(uploaded_file)
else:
    # On utilise le CSV enrichi (avec lat/lon)
    df, error = load_dataset("dataset_ssh.csv")

if error:
    st.error(f"❌ Erreur chargement : {error}")
    st.stop()

# ── FILTRES ────────────────────────────────────────────────────
st.sidebar.header("🎛️ Filtres")

event_list = sorted(df["EventId"].astype(str).unique())
event_choice = st.sidebar.selectbox(
    "Type d'événement",
    ["Tous"] + event_list,
)

ip_list = sorted(df["SourceIP"].dropna().astype(str).unique())
ip_choices = st.sidebar.multiselect(
    "Adresses IP",
    ip_list,
    default=ip_list,
)

user_choices = None
if "User" in df.columns:
    user_list = sorted(df["User"].dropna().astype(str).unique())
    user_choices = st.sidebar.multiselect(
        "Utilisateurs",
        user_list,
        default=user_list,
    )

df_filtered = df.copy()
if event_choice != "Tous":
    df_filtered = df_filtered[df_filtered["EventId"].astype(str) == event_choice]
df_filtered = df_filtered[df_filtered["SourceIP"].astype(str).isin(ip_choices)]
if user_choices is not None and len(user_choices) > 0:
    df_filtered = df_filtered[df_filtered["User"].astype(str).isin(user_choices)]

st.sidebar.write("---")
st.sidebar.metric("Événements filtrés", len(df_filtered))
st.sidebar.metric("IPs actives", df_filtered["SourceIP"].nunique())

if df_filtered.empty:
    st.warning("⚠️ Aucun résultat avec les filtres actuels.")
    st.stop()

# ── MÉTRIQUES ──────────────────────────────────────────────────
st.markdown("### 📊 Vue globale")

critical_ids = ["4625"]
df_filtered["Critique"] = df_filtered["EventId"].astype(str).isin(critical_ids)

col_m1, col_m2, col_m3, col_m4 = st.columns(4)
with col_m1:
    st.metric("Total événements", len(df_filtered))
with col_m2:
    st.metric("IPs uniques", df_filtered["SourceIP"].nunique())
with col_m3:
    st.metric(
        "Utilisateurs uniques",
        df_filtered["User"].nunique() if "User" in df_filtered.columns else 0,
    )
with col_m4:
    crit_count = df_filtered["Critique"].sum()
    st.metric("Événements critiques", int(crit_count))

st.markdown("---")

# ── IP AGRESSIVES (barres + camembert) ────────────────────────
st.markdown("### 🔥 IP agressives")

col_ip_left, col_ip_right = st.columns([1.2, 1])
colors = ["#2563EB", "#16A34A", "#F97316", "#E11D48", "#7C3AED"]

with col_ip_left:
    st.caption("Top 5 IP par nombre de tentatives")
    top_ips = df_filtered["SourceIP"].value_counts().head(5)

    fig, ax = plt.subplots(figsize=(6, 3))
    top_ips.plot(kind="barh", ax=ax, color=colors[: len(top_ips)])
    ax.set_xlabel("Tentatives")
    ax.set_ylabel("Adresse IP")
    ax.invert_yaxis()
    plt.tight_layout()
    st.pyplot(fig)

with col_ip_right:
    st.caption("Répartition (camembert) des top IP")
    if not top_ips.empty:
        fig, ax = plt.subplots(figsize=(5, 4))
        wedges, _, autotexts = ax.pie(
            top_ips.values,
            labels=None,
            autopct="%1.1f%%",
            startangle=90,
            colors=colors[: len(top_ips)],
            textprops={"color": "white"},
        )
        ax.axis("equal")
        ax.legend(
            wedges,
            top_ips.index,
            title="Adresses IP",
            loc="center left",
            bbox_to_anchor=(1, 0.5),
        )
        st.pyplot(fig)
    else:
        st.info("Pas de données pour le camembert.")

st.markdown("---")

# ── HISTOGRAMMES ──────────────────────────────────────────────
st.markdown("### 📶 Histogrammes")

col_h1, col_h2 = st.columns(2)

with col_h1:
    st.caption("Distribution du nombre de tentatives par IP")
    ip_counts = df_filtered["SourceIP"].value_counts()
    if not ip_counts.empty:
        fig, ax = plt.subplots(figsize=(5, 3))
        ax.hist(ip_counts.values, bins=10, edgecolor="black", color="#2563EB")
        ax.set_xlabel("Tentatives par IP")
        ax.set_ylabel("Nombre d'IP")
        plt.tight_layout()
        st.pyplot(fig)
    else:
        st.info("Pas de données suffisantes pour l'histogramme IP.")

with col_h2:
    st.caption("Répartition des EventId")
    fig, ax = plt.subplots(figsize=(5, 3))
    ax.hist(
        df_filtered["EventId"].astype(str),
        bins=len(df_filtered["EventId"].unique()),
        edgecolor="black",
        color="#16A34A",
    )
    ax.set_xlabel("EventId")
    ax.set_ylabel("Occurrences")
    plt.xticks(rotation=45)
    plt.tight_layout()
    st.pyplot(fig)

st.markdown("---")

# ── CARTE DES IP ──────────────────────────────────────────────
st.markdown("### 🌍 Carte des IP sources")

if all(col in df_filtered.columns for col in ["lat", "lon"]):
    df_ip_map = (
        df_filtered[["SourceIP", "lat", "lon"]]
        .dropna(subset=["lat", "lon"])
        .drop_duplicates(subset=["SourceIP"])
    )
    if not df_ip_map.empty:
        df_ip_map = df_ip_map.rename(columns={"lat": "latitude", "lon": "longitude"})
        st.map(df_ip_map)
    else:
        st.info("Aucune IP avec coordonnées pour afficher la carte.")
else:
    st.info("Le dataset ne contient pas de colonnes 'lat' et 'lon' pour afficher une carte des IP.")

st.markdown("---")

# ── TABLEAU + EXPORT ──────────────────────────────────────────
st.markdown("### 🔍 Données filtrées")
st.dataframe(df_filtered, use_container_width=True)

st.download_button(
    "📥 Télécharger le CSV filtré",
    df_filtered.to_csv(index=False),
    "ssh_logs_filtered.csv",
)
