import streamlit as st
import pandas as pd
import plotly.express as px

# Configuration de la page
st.set_page_config(
    page_title="SSH Monitor",
    page_icon="🛡️",
    layout="wide"
)

def display_dashboard(df, filter_placeholder):
    """
    Affiche le tableau de bord.
    filter_placeholder : L'endroit précis dans la sidebar où injecter les filtres.
    """
    
    # --- 1. Remplissage des Filtres (Injectés en HAUT de la sidebar) ---
    with filter_placeholder.container():
        st.header("Filtres du Dashboard")
        st.write(f"📊 **{len(df)}** événements chargés")

        # Filtre par EventId
        if "EventId" in df.columns:
            event_ids = df["EventId"].astype(str).unique()
            event_choice = st.selectbox(
                "Filtrer par type d'événement (EventId)",
                options=["Tous"] + sorted(list(set(event_ids)))
            )
        else:
            event_choice = "Tous"

        # Filtre par IP source
        if "SourceIP" in df.columns:
            ips_series = df["SourceIP"].astype(str)
            ips_unique = ips_series.dropna().unique()
            ips_list = sorted(list(set(ips_unique)))
            ip_choices = st.multiselect(
                "Filtrer par IP source",
                options=ips_list,
                default=[]
            )
        else:
            ip_choices = []
            
        st.markdown("---") # Séparateur visuel avant l'upload qui est techniquement en dessous

    # --- 2. Application des filtres sur les données ---
    df_filtered = df.copy()

    if event_choice != "Tous" and "EventId" in df_filtered.columns:
        df_filtered = df_filtered[df_filtered["EventId"].astype(str) == event_choice]

    if ip_choices and "SourceIP" in df_filtered.columns:
        df_filtered = df_filtered[df_filtered["SourceIP"].astype(str).isin(ip_choices)]

    # Si tout est filtré, on arrête l'affichage graphiques
    if df_filtered.empty:
        st.warning("Aucun résultat avec ces filtres. Ajustez vos sélections.")
        return

    # --- 3. Affichage Principal (Centre de la page) ---
    # KPIs
    st.markdown("### Indicateurs Clés")
    col1, col2, col3 = st.columns(3)

    total_events = len(df_filtered)
    unique_ips = df_filtered["SourceIP"].nunique() if "SourceIP" in df_filtered.columns else 0
    target_users = df_filtered["User"].nunique() if "User" in df_filtered.columns else 0

    with col1: st.metric("Total Événements", total_events)
    with col2: st.metric("IPs Uniques", unique_ips)
    with col3: st.metric("Utilisateurs visés", target_users)

    st.markdown("---")

    # Graphiques
    col_left, col_right = st.columns(2)

    with col_left:
        if "SourceIP" in df_filtered.columns:
            st.subheader("Top 20 des adresses IP sources")
            top20 = df_filtered["SourceIP"].value_counts().head(20).reset_index()
            top20.columns = ["SourceIP", "Events"]
            
            fig_bar = px.bar(top20, x="SourceIP", y="Events", title="Top 20 IP sources")
            fig_bar.update_layout(xaxis_tickangle=-90)
            st.plotly_chart(fig_bar, use_container_width=True)

            st.subheader("Répartition Top 10 IP")
            top10 = df_filtered["SourceIP"].value_counts().head(10).reset_index()
            top10.columns = ["SourceIP", "Events"]
            fig_pie = px.pie(top10, names="SourceIP", values="Events", title="Part des événements (Top 10)")
            st.plotly_chart(fig_pie, use_container_width=True)

    with col_right:
        if "Timestamp" in df_filtered.columns:
            st.subheader("Évolution temporelle (par heure)")
            df_time = df_filtered.copy()
            df_time["Timestamp"] = pd.to_datetime(df_time["Timestamp"], format="%b %d %H:%M:%S", errors="coerce")
            df_time = df_time.dropna(subset=["Timestamp"])
            
            if not df_time.empty:
                attacks_by_time = df_time.set_index("Timestamp").resample("H").size()
                st.line_chart(attacks_by_time)

    with st.expander("Voir les données tabulaires filtrées"):
        st.dataframe(df_filtered)


def main():
    st.title("🛡️ Analyseur de Logs SSH")

    # --- SIDEBAR CONFIGURATION ---
    
    # 1. On crée un ESPACE VIDE (Placeholder) tout en haut de la sidebar
    # C'est ici que les filtres s'afficheront une fois les données chargées
    sidebar_filters_placeholder = st.sidebar.empty()

    # 2. On place l'Input File Uploader EN DESSOUS
    # Il est techniquement après le placeholder
    st.sidebar.markdown("### Source des données")
    uploaded_file = st.sidebar.file_uploader(
        "Charger un fichier (CSV ou Log)", 
        type=['csv', 'log', 'txt']
    )

    # --- LOGIQUE PRINCIPALE ---
    if uploaded_file is not None:
        file_name = uploaded_file.name
        
        # CAS A : CSV
        if file_name.endswith('.csv'):
            try:
                df = pd.read_csv(uploaded_file)
                st.success(f"Mode Dashboard activé : {file_name}")
                # On appelle la fonction en lui donnant l'adresse du placeholder
                display_dashboard(df, sidebar_filters_placeholder)
            except Exception as e:
                st.error(f"Erreur CSV : {e}")

        # CAS B : LOG BRUT (Parsing simple)
        else:
            try:
                log_data = uploaded_file.getvalue().decode("utf-8")
                lines = log_data.splitlines()
                st.success(f"Mode Brut : {len(lines)} lignes chargées.")
                
                # Visualisation simple pour le log brut
                st.subheader("Aperçu du contenu brut")
                for line in lines[:5]:
                    st.text(line)
                with st.expander("Voir tout le fichier"):
                    st.text(log_data)
                    
            except Exception as e:
                st.error(f"Erreur Lecture Log : {e}")

    else:
        # Message d'accueil si rien n'est chargé
        st.info("👈 Veuillez charger un fichier dans la barre latérale pour commencer.")

if __name__ == "__main__":
    main()
