# Projet_Python_HannaGerguis_Pasquet_Kabir
# Lien YouTube vers démonstration du projet : https://youtu.be/urXzGSPnAbY
# 🛡️ Outil d'Automatisation de la Cybersurveillance ANSSI (CVE/EPSS)

## 🎯 Aperçu du Projet

Ce projet vise à développer un outil Python entièrement automatisé pour surveiller proactivement les menaces de sécurité basées sur les publications de l'**Agence Nationale de la Sécurité des Systèmes d'Information (ANSSI)**.

En transformant les bulletins bruts en données exploitables et en générant des alertes ciblées, l'outil permet d'anticiper l'impact des vulnérabilités critiques sur les systèmes.

---

## 🚀 Objectifs et Fonctionnalités Clés

L'outil exécute une chaîne de traitement complète, de la collecte d'information brute à la génération d'alertes :

### 1. Extraction et Traitement des Données
* **Collecte :** Extraction automatisée des données via le **flux RSS de l'ANSSI**.
* **Parsing :** Traitement et désérialisation des bulletins au format **JSON**.

### 2. Enrichissement et Qualification des Menaces
* **Identification CVE :** Identification des références de vulnérabilités (CVE) dans les bulletins.
* **Enrichissement API :** Utilisation d'APIs externes pour qualifier la menace :
    * **MITRE :** Récupération des scores de gravité **CVSS** (Common Vulnerability Scoring System) et des faiblesses **CWE** (Common Weakness Enumeration).
    * **FIRST :** Ajout du score **EPSS** (Exploit Prediction Scoring System) pour évaluer la probabilité d'exploitation.

### 3. Analyse et Visualisation
* **Data Consolidation :** Structuration et consolidation de toutes les données enrichies dans un **DataFrame Pandas**.
* **Rapports :** Visualisation des données (Matplotlib/Plotly) pour analyser :
    * La gravité des menaces (CVSS).
    * Les tendances d'exploitabilité (EPSS).
    * L'impact sectoriel par éditeur.

### 4. Notification
* **Génération d'Alertes :** Application de règles personnalisées pour identifier les vulnérabilités jugées critiques.
* **Envoi d'E-mails :** Génération et envoi automatisé des bulletins d'alerte par e-mail aux destinataires concernés.

---

## ✅ Compétences Développées

Ce projet a permis de développer une expertise à la croisée du développement et de la cybersécurité :

### Compétences Techniques
* **Développement :** Maîtrise de **Python** pour l'automatisation.
* **API & Données :** Utilisation d'**API REST** pour l'enrichissement des données et manipulation via la librairie **Pandas**.
* **Visualisation :** Création de tableaux de bord et graphiques avec **Matplotlib** et **Plotly**.
* **Traitement de Texte :** Utilisation des expressions régulières (**regex
