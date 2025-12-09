import streamlit as st
import pandas as pd
import plotly.express as px

# Configuration de la page
st.set_page_config(
    page_title="SSH Monitor",
    page_icon="🛡️",
    layout="wide"
)

def display_dashboard(df):
    """
    Affiche le tableau de bord graphique si les données sont structurées (CSV).
    """
    # --- Sidebar Filtres (Uniquement si Dashboard actif) ---
    st.sidebar.header("Filtres du Dashboard")
    st.sidebar.write(f"{len(df)} événements chargés")

    # Filtre par EventId
    if "EventId" in df.columns:
        event_ids = df["EventId"].astype(str).unique()
        event_choice = st.sidebar.selectbox(
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
        ip_choices = st.sidebar.multiselect(
            "Filtrer par IP source",
            options=ips_list,
            default=[]
        )
    else:
        ip_choices = []

    # --- Application des filtres ---
    df_filtered = df.copy()

    if event_choice != "Tous" and "EventId" in df_filtered.columns:
        df_filtered = df_filtered[df_filtered["EventId"].astype(str) == event_choice]

    if ip_choices and "SourceIP" in df_filtered.columns:
        df_filtered = df_filtered[df_filtered["SourceIP"].astype(str).isin(ip_choices)]

    if df_filtered.empty:
        st.warning("Aucun résultat avec ces filtres. Ajustez vos sélections.")
        return

    # --- KPIs ---
    st.markdown("### Indicateurs Clés")
    col1, col2, col3 = st.columns(3)

    total_events = len(df_filtered)
    # Gestion des erreurs si les colonnes manquent
    unique_ips = df_filtered["SourceIP"].nunique() if "SourceIP" in df_filtered.columns else 0
    target_users = df_filtered["User"].nunique() if "User" in df_filtered.columns else 0

    with col1:
        st.metric("Total Événements", total_events)
    with col2:
        st.metric("IPs Uniques", unique_ips)
    with col3:
        st.metric("Utilisateurs visés", target_users)

    st.markdown("---")

    # --- Analyses visuelles ---
    col_left, col_right = st.columns(2)

    # Top 20 IPs
    with col_left:
        if "SourceIP" in df_filtered.columns:
            st.subheader("Top 20 des adresses IP sources")
            top20 = df_filtered["SourceIP"].value_counts().head(20).reset_index()
            top20.columns = ["SourceIP", "Events"]
            
            fig_bar = px.bar(
                top20,
                x="SourceIP",
                y="Events",
                title="Top 20 IP sources",
                labels={"SourceIP": "Adresse IP", "Events": "Nombre d'événements"}
            )
            fig_bar.update_layout(xaxis_tickangle=-90)
            st.plotly_chart(fig_bar, use_container_width=True)

            # Camembert Top 10
            st.subheader("Répartition Top 10 IP")
            top10 = df_filtered["SourceIP"].value_counts().head(10).reset_index()
            top10.columns = ["SourceIP", "Events"]
            fig_pie = px.pie(top10, names="SourceIP", values="Events", title="Part des événements (Top 10)")
            st.plotly_chart(fig_pie, use_container_width=True)

    # Évolution temporelle
    with col_right:
        if "Timestamp" in df_filtered.columns:
            st.subheader("Évolution temporelle (par heure)")
            df_time = df_filtered.copy()
            df_time["Timestamp"] = pd.to_datetime(
                df_time["Timestamp"],
                format="%b %d %H:%M:%S", # Format à adapter selon vos logs
                errors="coerce"
            )
            df_time = df_time.dropna(subset=["Timestamp"])
            
            if not df_time.empty:
                attacks_by_time = df_time.set_index("Timestamp").resample("H").size()
                st.line_chart(attacks_by_time)
            else:
                st.info("Format de date non reconnu ou données vides.")

    # Données brutes filtrées
    with st.expander("Voir les données tabulaires filtrées"):
        st.dataframe(df_filtered)


def main():
    st.title("🛡️ Analyseur de Logs SSH")

    # 1. Zone d'upload (au centre ou sidebar selon préférence)
    st.info("Commencez par charger un fichier de logs ou un dataset CSV.")
    
    uploaded_file = st.file_uploader(
        "Choisissez votre fichier (CSV structuré ou Log brut .txt/.log)", 
        type=['csv', 'log', 'txt']
    )

    # 2. Vérification et Aiguillage
    if uploaded_file is not None:
        file_name = uploaded_file.name
        
        # CAS A : Fichier CSV (Données déjà structurées) -> On lance le Dashboard
        if file_name.endswith('.csv'):
            try:
                df = pd.read_csv(uploaded_file)
                st.success(f"Fichier CSV '{file_name}' chargé avec succès !")
                display_dashboard(df)
            except Exception as e:
                st.error(f"Erreur lors de la lecture du CSV : {e}")

        # CAS B : Fichier LOG/TXT (Données brutes) -> On lance l'analyseur de texte
        else:
            try:
                # Lecture et décodage
                log_data = uploaded_file.getvalue().decode("utf-8")
                lines = log_data.splitlines()
                
                st.success(f"Fichier Log brut '{file_name}' chargé ! {len(lines)} lignes détectées.")
                
                st.warning("⚠️ Vous visualisez un fichier brut. Pour voir les graphiques, le fichier doit être converti en CSV (parsing).")

                # Affichage des données brutes
                st.subheader("Aperçu du contenu brut")
                
                # On affiche les 10 premières lignes pour l'exemple
                for i, line in enumerate(lines[:10]):
                    st.text(f"Ligne {i+1}: {line}")
                
                with st.expander("Voir tout le contenu du fichier"):
                    st.text(log_data)

            except Exception as e:
                st.error(f"Erreur lors de la lecture du fichier Log : {e}")

    else:
        # État initial (aucun fichier)
        st.write("waiting for file upload...")

if __name__ == "__main__":
    main()
