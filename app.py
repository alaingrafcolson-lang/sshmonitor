import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px

st.set_page_config(
    page_title="SSH Monitor",
    page_icon="🖥️",
    layout="wide"
)

@st.cache_data
def load_data():
    df = pd.read_csv("datasetssh.csv")
    return df

def main():
    df = load_data()

    # Titre principal
    st.title("Indicateurs Clés")

    # Sidebar
    st.sidebar.title("Filtres")
    st.sidebar.write(f"{len(df)} événements chargés")

    # --- Widgets de filtres ---

    # Filtre par EventId
    event_ids = df["EventId"].astype(str).unique()
    event_choice = st.sidebar.selectbox(
        "Filtrer par type d'événement (EventId)",
        options=["Tous"] + sorted(list(set(event_ids)))
    )

    # Filtre par IP source
    ips_series = df["SourceIP"].astype(str)
    ips_unique = ips_series.dropna().unique()
    ips_list = sorted(list(set(ips_unique)))

    ip_choices = st.sidebar.multiselect(
        "Filtrer par IP source",
        options=ips_list,
        default=[]
    )

    # --- Application des filtres ---
    df_filtered = df.copy()

    if event_choice != "Tous":
        df_filtered = df_filtered[df_filtered["EventId"].astype(str) == event_choice]

    if ip_choices:
        df_filtered = df_filtered[df_filtered["SourceIP"].astype(str).isin(ip_choices)]

    if df_filtered.empty:
        st.warning("Aucun résultat avec ces filtres. Ajustez vos sélections.")

    # Trois colonnes de métriques
    col1, col2, col3 = st.columns(3)

    total_events = len(df_filtered)
    unique_ips = df_filtered["SourceIP"].nunique()
    target_users = df_filtered["User"].nunique()

    with col1:
        st.metric("Total Événements", total_events)

    with col2:
        st.metric("IPs Uniques", unique_ips)

    with col3:
        st.metric("Utilisateurs visés", target_users)

    st.markdown("---")
    st.subheader("Analyses visuelles")

    # Deux colonnes pour les graphes principaux
    col_left, col_right = st.columns(2)

    # Top 20 IPs en colonnes Plotly (gauche)
    with col_left:
        st.subheader("Top 20 des adresses IP sources (colonnes)")
        top20 = df_filtered["SourceIP"].value_counts().head(20).reset_index()
        top20.columns = ["SourceIP", "Events"]

        if top20.empty:
            st.info("Aucune donnée à afficher pour ce graphique avec les filtres actuels.")
        else:
            fig_bar = px.bar(
                top20,
                x="SourceIP",
                y="Events",
                title="Top 20 IP sources",
                labels={"SourceIP": "Adresse IP", "Events": "Nombre d'événements"}
            )
            fig_bar.update_layout(xaxis_tickangle=-90)
            st.plotly_chart(fig_bar, use_container_width=True)

        # Camembert des Top 10 IP sources
        st.subheader("Répartition des Top 10 IP sources")
        top10 = df_filtered["SourceIP"].value_counts().head(10).reset_index()
        top10.columns = ["SourceIP", "Events"]

        if top10.empty:
            st.info("Aucune donnée à afficher pour ce graphique avec les filtres actuels.")
        else:
            fig_pie = px.pie(
                top10,
                names="SourceIP",
                values="Events",
                title="Part des événements par IP (Top 10)"
            )
            st.plotly_chart(fig_pie, use_container_width=True)

    # Évolution temporelle des attaques (droite)
    with col_right:
        st.subheader("Évolution temporelle des attaques (par heure)")
        df_time = df_filtered.copy()
        df_time["Timestamp"] = pd.to_datetime(
            df_time["Timestamp"],
            format="%b %d %H:%M:%S",
            errors="coerce"
        )
        df_time = df_time.dropna(subset=["Timestamp"])

        if df_time.empty:
            st.info("Aucune donnée temporelle à afficher avec les filtres actuels.")
        else:
            attacks_by_time = df_time.set_index("Timestamp").resample("H").size()
            st.line_chart(attacks_by_time)

    # Données brutes
    st.markdown("---")
    with st.expander("Voir les données brutes filtrées"):
        st.dataframe(df_filtered)

if __name__ == "__main__":
    main()

