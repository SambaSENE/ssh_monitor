@"
# MonitorSSH - Dashboard SSH Interactif

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28%2B-red)](https://streamlit.io)
[![License MIT](https://img.shields.io/badge/License-MIT-green)](#)

Dashboard professionnel pour l'analyse en temps réel des logs SSH avec filtrage dynamique et visualisations interactives.

## 🎯 Caractéristiques

- **4 Métriques KPI** : Total événements, IPs uniques, tentatives/IP, types d'événements
- **Visualisations** : Top 5 IPs, distribution d'événements
- **Filtrage dynamique** : Selectbox EventId + Multiselect IPs
- **Performance optimisée** : Caching intelligent avec @st.cache_data
- **Export CSV** : Télécharger les données filtrées
- **Design pro** : Thème bleu marine avec interface responsive

## 🚀 Installation Rapide

### Prérequis
- Python 3.8+
- Git

### Démarrage Local

\`\`\`bash
# Cloner le repo
git clone https://github.com/TON_USERNAME/SSH_monitor.git
cd SSH_monitor

# Créer environnement virtuel
python -m venv .venv
.\.venv\Scripts\Activate.ps1  # Windows PowerShell

# Installer dépendances
pip install -r requirements.txt

# Lancer l'app
streamlit run app.py
\`\`\`

L'app s'ouvrira à `http://localhost:8501`

## 📖 Utilisation

1. **Filtrer par événement** : Selectbox \"Type d'événement\"
2. **Filtrer par IP** : Multiselect \"Adresses IP\"
3. **Explorer les graphiques** : Mise à jour instantanée
4. **Télécharger** : Bouton \"Télécharger CSV\"

## 🌐 Déploiement Cloud

Application déployée sur **Streamlit Community Cloud** :

👉 [ssh-monitor-XXXXX.streamlit.app](https://ssh-monitor-XXXXX.streamlit.app)

### Déployer votre version

1. Pusher le code sur GitHub
2. Aller sur [share.streamlit.io](https://share.streamlit.io)
3. Cliquer \"Create app\" → Sélectionner repo + app.py
4. Déploiement automatique ✅

## 📁 Structure

\`\`\`
ssh_monitor/
├── .venv/              # Env virtuel
├── app.py              # Application Streamlit
├── dataset_ssh.csv     # Données
├── requirements.txt    # Dépendances
├── .gitignore
└── README.md
\`\`\`

## 🛠️ Stack

| Composant | Technologie |
|-----------|-------------|
| Frontend | Streamlit + Matplotlib |
| Backend | Python + Pandas |
| Déploiement | Streamlit Cloud + GitHub |
| Versionning | Git |

## ✅ Critères du Brief

- ✅ Widgets de filtrage fonctionnels
- ✅ Réactivité instantanée (caching)
- ✅ Gestion des erreurs complète
- ✅ Structure projet propre (.gitignore)
- ✅ Code optimisé et commenté
- ✅ Déploiement en ligne

## 📚 Technologies Clés

- **@st.cache_data** : Optimisation performances
- **st.columns()** : Layout responsive
- **st.sidebar** : Filtres isolés
- **Pandas filtering** : Manipulations données
- **Matplotlib** : Visualisations

## 📧 Informations

- **Projet** : Brief Simplon - GDE Nancy Cyber
- **Durée** : 2 jours (Jour 1: Architecture | Jour 2: Interactivité + Déploiement)
- **Status** : ✅ Complet et en production

---

**Dernière mise à jour** : Décembre 2025
"@ | Out-File -Encoding UTF8 README.md
