# Projet Final — Mastercamp 2025

Projet réalisé dans le cadre du Mastercamp Efrei 2025. Il vise à mettre en place une chaîne complète de traitement de données de cybersécurité, incluant leur visualisation, leur analyse, et la détection d’incidents à l’aide de techniques de machine learning.

---

## Objectifs pédagogiques

- Approfondir les compétences en **data science** et **cybersécurité**
- Concevoir une solution technique à partir d’un **problème métier réel**
- Utiliser le **machine learning** pour détecter des comportements suspects
- Implémenter un système d’**alerte automatisée** par email

---

## Structure du projet

mastercamp-projet-final-main/
│
├── main.py # Script principal du projet
├── main.ipynb # Version notebook pour exécution interactive
├── machine_learning.ipynb # Analyse, modélisation, prédictions
├── Visualisation_ANSSI.ipynb # Dashboards et représentations graphiques
├── Alerte_email.ipynb # Script d'alerte en cas de détection
│
├── DataFrame_Complet.csv # Jeu de données pré-traité
├── Sujet_Projet_Mastercamp_2025.pdf # Cahier des charges initial
└── contributions.txt # Répartition des rôles


---

## Technologies utilisées

- **Python 3**
- **Jupyter Notebook**
- **pandas, numpy** : manipulation de données
- **matplotlib, seaborn** : visualisation
- **scikit-learn** : machine learning
- **smtplib** : envoi d’emails
- **joblib** : sérialisation des modèles

---

## Installation et exécution

1. **Cloner le dépôt**
   ```bash
   git clone https://github.com/<utilisateur>/mastercamp-projet-final.git
   cd mastercamp-projet-final
---
## Fonctionnalités principales

- Chargement et nettoyage des données de cybersécurité

- Visualisation des tendances et des incidents

- Détection automatique d'anomalies via modèles supervisés

- Système d’envoi d’alertes par email en cas de détection
  
---
## Alertes Email

Le notebook Alerte_email.ipynb permet d’envoyer des notifications automatiques par email si un comportement suspect est détecté. 
Le script fourni un example d'usage du jeu de donner pour envoyer des alertes avec une email test ethereal.emai pour voir les emails envoyer par l'email test 'riley.cormier37@ethereal.email', 'APvJGZdFEKnu22MSuQ'

---
## Remarques

Le projet peut être enrichi avec :

- Une interface utilisateur graphique

- L’intégration d’une base de données (SQLite, PostgreSQL)

- Un déploiement sous forme de dashboard web (Streamlit, Dash)



