import schedule #Pour une implémentation future, pour programme l'execution du code (si hébergement possible)
import feedparser
import pandas as pd
import requests
import re
import time
import smtplib
import os 
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart



####################
# Variables globales 
####################


fichier_csv = os.path.dirname(os.path.abspath(__file__))
fichier_csv = os.path.join(fichier_csv, 'tous_les_cve.csv')
if os.path.exists(fichier_csv):
    print(f"Fichier CSV trouvé")
else:
    print(f"Fichier CSV introuvable : {fichier_csv}")


chemin_logo = os.path.dirname(os.path.abspath(__file__))
chemin_logo = os.path.join(chemin_logo, "logo_anssi.png")

if os.path.exists(chemin_logo):
    print(f"Logo ANSSI trouvé")
else:
    print(f"Logo ANSSI introuvable : {chemin_logo}")

liste_email = ["anonyme@anonyme.fr"]  # Liste des destinataires (pour pouvoir tester l'envoie d'email, peut etre utile en cas de database des abonnes sur mysql)


from_email = "certfr.anssi@gmail.com"
from_mdp = "enzg kpds wcwy pbej"  # mot de passe d'application
from_nom = "CERT FR"
serveur_smtp = "smtp.gmail.com"
port_smtp = 587


urls_rss = [
    "https://www.cert.ssi.gouv.fr/avis/feed/",
    "https://www.cert.ssi.gouv.fr/alerte/feed/",
    "https://www.cert.ssi.gouv.fr/actualite/feed/"
]







##################################
# Etape 1. Extraction des flux RSS
##################################

def extraction_data_rss(liste_urls):
    data = []
    # Headers pour imiter un navigateur (indispensable pour l'ANSSI)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    print(f"Début de l'extraction sur {len(liste_urls)} flux RSS...")

    for lien_rss in liste_urls:
        try:
            print(f" - Téléchargement de : {lien_rss}")
            reponse = requests.get(lien_rss, headers=headers, timeout=15)
            
            # On vérifie si le téléchargement a réussi
            if reponse.status_code != 200:
                print(f"   [ERREUR] Code HTTP {reponse.status_code} pour {lien_rss}")
                continue

            # Parsing du contenu
            flux_rss = feedparser.parse(reponse.content)
            
            nombre_entrees = len(flux_rss.entries)
            print(f"   -> Succès : {nombre_entrees} articles trouvés dans ce flux.")

            if nombre_entrees == 0:
                print("   [ATTENTION] Le flux est vide ou mal lu.")
                continue

            for entree in flux_rss.entries:
                # Recherche du type (AVI, ALE, etc.) dans le LIEN
                id_cert = re.search(r"\b(ACT|AVI|ALE|CTI|IOC|DUR)\b", entree.link)
                if id_cert:
                    id_type = id_cert.group(1)
                    if id_type == "ALE": type_bulletin = "Alerte"
                    elif id_type == "AVI": type_bulletin = "Avis"
                    elif id_type == "ACT": type_bulletin = "Bulletin d'actualité"
                    elif id_type == "CTI": type_bulletin = "Rapport CTI"
                    elif id_type == "IOC": type_bulletin = "Indicateurs de Compromission"
                    elif id_type == "DUR": type_bulletin = "Recommandation"
                    else: type_bulletin = "Inconnu"
                else:
                    type_bulletin = "Inconnu"

                data_stock = {
                    "Titre": entree.title,
                    "Type": type_bulletin,
                    "Date": entree.published,
                    "Description": entree.description,
                    "Lien": entree.link
                }
                data.append(data_stock)

        except Exception as e:
            print(f"   [CRITIQUE] Erreur technique sur {lien_rss} : {e}")

    print(f"Total des articles extraits : {len(data)}")
    return pd.DataFrame(data)

####################################
# Etape 2. Extraction des CVE (JSON)
####################################

def extraction_cve_from_page(lien):
    liste_cve = []
    try:
        # On définit un User-Agent pour ne pas être bloqué par le pare-feu du site
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # On récupère directement le lien (sans ajouter /json/)
        reponse = requests.get(lien, headers=headers, timeout=10)
        
        if reponse.status_code == 200:
            # On cherche les CVE directement dans le texte HTML de la page
            contenu_page = reponse.text
            motif_cve = r"CVE-\d{4}-\d{4,7}"
            liste_cve = list(set(re.findall(motif_cve, contenu_page)))
        else:
            print(f"Erreur HTTP {reponse.status_code} pour {lien}")

    except Exception as e:
        # On ignore les erreurs sur les bulletins d'actualité qui contiennent rarement des CVE structurés de la même façon
        if "ACT" not in lien:  
            print(f"Erreur lors de la lecture de {lien} : {e}")       
            
    return liste_cve

############################################
# Etape 3. Enrichissement CVE via MITRE API
############################################
def enrichir_cve_mitre(id_cve):
    adresse_api = f"https://cveawg.mitre.org/api/cve/{id_cve}"
    try:
        reponse_api = requests.get(adresse_api, timeout=10)
        reponse_api.raise_for_status()
        donnees_reponse = reponse_api.json()
        cna_data = donnees_reponse.get("containers", {}).get("cna", {})
        adp_data = donnees_reponse.get("adp", [])

        # Description
        description = "Non disponible"
        if "descriptions" in cna_data:
            description = cna_data["descriptions"][0].get("value", "Non disponible")

        # Score CVSS
        bloc_metrics = cna_data.get("metrics", [])
        if bloc_metrics:
            cvss_data = bloc_metrics[0].get("cvssV3_1", {})
            cvss_score = cvss_data.get("baseScore", "Non disponible")
            if cvss_score != "Non disponible":
                note_float = float(cvss_score)
                if note_float >= 9:
                    base_severity = "Critique"
                elif note_float >= 7:
                    base_severity = "Élevée"
                elif note_float >= 4:
                    base_severity = "Moyenne"
                else:
                    base_severity = "Faible"
            else:
                cvss_score = "Non disponible"
                base_severity = "Non disponible"
        else:
            cvss_score = "Non disponible"
            base_severity = "Non disponible"

        # CWE depuis "containers.cna"
        problem_types = cna_data.get("problemTypes", [])
        cwe = "Non disponible"
        cwe_description = "Non disponible"
        if problem_types and "descriptions" in problem_types[0]:
            cwe_info = problem_types[0]["descriptions"][0]
            cwe = cwe_info.get("cweId", "Non disponible")
            cwe_description = cwe_info.get("description", "Non disponible")

        # Si pas de CWE dans "cna" on cherche dans "adp"
        if cwe == "Non disponible" and adp_data:
            for adp_entry in adp_data:
                problem_types = adp_entry.get("problemTypes", [])
                if problem_types:
                    cwe_info = problem_types[0].get("descriptions", [{}])[0]
                    cwe = cwe_info.get("cweId", cwe)
                    cwe_description = cwe_info.get("description", cwe_description)
                    break

        # Produits affectés --> et donc versions et vendeurs
        affectes = cna_data.get("affected", [])
        vendeurs = []
        produits = []
        versions_affectees = []
        for element in affectes:
            vendeurs.append(element.get("vendor", "Non disponible"))
            produits.append(element.get("product", "Non disponible"))
            for version_info in element.get("versions", []):
                if version_info.get("status") == "affected":
                    versions_affectees.append(version_info.get("version", "Non disponible"))

        return {
            "Description": description,
            "CVSS Score": cvss_score,
            "Base Severity": base_severity,
            "CWE": cwe,
            "CWE Description": cwe_description,
            "Produits Affectés": ", ".join(produits) if produits else "Non disponible",
            "Versions Affectées": ", ".join(versions_affectees) if versions_affectees else "Non disponible",
            "Vendeur": ", ".join(set(vendeurs)) if vendeurs else "Non disponible"
        }

    except Exception as e:
        print(f"Erreur pour le CVE {id_cve} : {e}")
        return {
            "Description": "Erreur",
            "CVSS Score": "Non disponible",
            "Base Severity": "Non disponible",
            "CWE": "Non disponible",
            "CWE Description": "Non disponible",
            "Produits Affectés": "Non disponible",
            "Versions Affectées": "Non disponible",
            "Vendeur": "Non disponible"
        }

#####################################
# Etape 4. Consolidation dans le CSV
#####################################

def enrichir_cve_df(donnees_rss, delay=1):
    colonnes_enrichies = []
    if os.path.exists(fichier_csv):
        try:
            df_existants = pd.read_csv(fichier_csv)
            cve_existants = set(df_existants['CVE'].dropna())
            titres_existants = set(df_existants['Titre ANSSI'].dropna())
            print(f"        - {len(cve_existants)} CVE existants chargés depuis {fichier_csv}.")
        except Exception as e:
            print(f"        - Erreur lors du chargement du fichier CSV : {e}")
            cve_existants = set()
            titres_existants = set()
            df_existants = pd.DataFrame()
    else:
        print(f"        - Aucun fichier existant trouvé. Création d'un nouveau fichier {fichier_csv}.")
        cve_existants = set()
        titres_existants = set()
        df_existants = pd.DataFrame()

    for _, ligne in donnees_rss.iterrows():
        if ligne["Type"] == "Bulletin d'actualité":
            if ligne["Titre"] not in titres_existants:
                colonnes_enrichies.append({
                    "Titre ANSSI": ligne.get("Titre", "Non disponible"),
                    "Type": ligne.get("Type", "Non disponible"),
                    "Date": ligne.get("Date", "Non disponible"),
                    "Lien": ligne.get("Lien", "Non disponible"),
                    "Description": ligne.get("Description", "Non disponible"),
                    "CVE": "Aucun",
                    "CVSS Score": "Non applicable",
                    "Base Severity": "Non applicable",
                    "CWE": "Non applicable", 
                    "CWE Description": "Non applicable",
                    "Versions Affectées": "Non applicable",
                    "Produits Affectés": "Non applicable",
                    "Vendeur": "Non applicable"
                })
            continue

        liste_cve = ligne.get("CVE", [])
        if liste_cve:
            for cve_trouve in liste_cve:
                if cve_trouve not in cve_existants:
                    colonnes_enrichies.append({
                        "Titre ANSSI": ligne.get("Titre", "Non disponible"),
                        "Type": ligne.get("Type", "Non disponible"),
                        "Date": ligne.get("Date", "Non disponible"),
                        "Lien": ligne.get("Lien", "Non disponible"),
                        "Description": ligne.get("Description", "Non disponible"),
                        "CVE": cve_trouve,
                        "CWE": "Non disponible", 
                        "CWE Description": "Non disponible"  
                    })
        else:
            if ligne["Titre"] not in titres_existants:
                colonnes_enrichies.append({
                    "Titre ANSSI": ligne.get("Titre", "Non disponible"),
                    "Type": ligne.get("Type", "Non disponible"),
                    "Date": ligne.get("Date", "Non disponible"),
                    "Lien": ligne.get("Lien", "Non disponible"),
                    "Description": ligne.get("Description", "Non disponible"),
                    "CVE": "Aucun",
                    "CVSS Score": "Non applicable",
                    "Base Severity": "Non applicable",
                    "CWE": "Non applicable",  
                    "CWE Description": "Non applicable",  
                    "Versions Affectées": "Non applicable",
                    "Produits Affectés": "Non applicable",
                    "Vendeur": "Non applicable"
                })

    print(f"          {len(colonnes_enrichies)} nouveaux éléments détectés à enrichir.")

    # Enrichir avec la data MITRE
    for idx, cve_data in enumerate(colonnes_enrichies, start=1):
        if cve_data["CVE"] != "Aucun":
            print(f"Enrichissement pour le CVE {cve_data['CVE']} ({idx}/{len(colonnes_enrichies)})...") #On sait comme ca combien de temps à peu près le programme va prendre
            donnees_mitre = enrichir_cve_mitre(cve_data['CVE'])
            cve_data.update({
                "CVSS Score": donnees_mitre["CVSS Score"],
                "Base Severity": donnees_mitre["Base Severity"],
                "Description": donnees_mitre["Description"] or cve_data["Description"],
                "CWE": donnees_mitre["CWE"], 
                "CWE Description": donnees_mitre["CWE Description"], 
                "Versions Affectées": donnees_mitre["Versions Affectées"],
                "Produits Affectés": donnees_mitre["Produits Affectés"],
                "Vendeur": donnees_mitre["Vendeur"]
            })
            time.sleep(delay)

    if colonnes_enrichies:
        df_nouveaux = pd.DataFrame(colonnes_enrichies)
        df_mis_a_jour = pd.concat([df_existants, df_nouveaux], ignore_index=True)
        try:
            df_mis_a_jour.to_csv(fichier_csv, index=False)
            print(f"          Fichier CSV mis à jour avec {len(df_nouveaux)} nouveaux éléments ajoutés.")
        except Exception as e:
            print(f"          Erreur lors de la mise à jour du fichier CSV : {e}")
    else:
        print("     - Aucun nouveau CVE ou bulletin à enrichir.")

    return pd.DataFrame(colonnes_enrichies)


########################################
# Etape 6. Générer un mail groupé (HTML)
########################################

def creer_html_bulletins_sans_vendeur(df_bulletins): #Juste pour les bulletins d'actualites, car on n'a pas de vendeurs pour les bulletins
    if df_bulletins.empty:
        return "<p>Aucune donnée disponible.</p>"

    html_bulletins = "<ul style='margin-left: 20px;'>"
    for _, ligne_bulletin in df_bulletins.iterrows():
        html_bulletins += f"""
        <li style="margin-bottom: 10px;">
            <strong>Titre:</strong> {ligne_bulletin.get('Titre ANSSI', 'Non disponible')}<br>
            <strong>Date:</strong> {ligne_bulletin.get('Date', 'Non disponible')}<br>
            <strong>Description:</strong> {ligne_bulletin.get('Description', 'Non disponible')}<br>
            <a href="{ligne_bulletin.get('Lien', '#')}" target="_blank">Lien vers le détail</a>
        </li>
        """
    html_bulletins += "</ul>"
    return html_bulletins


def creer_html_par_vendeur(df):
    if df.empty:
        return "<p>Aucune donnée disponible.</p>"
    df_copie = df.copy()

    df_copie['Vendeur'] = df_copie['Vendeur'].apply(normaliser_vendeur)
    groupes = df_copie.groupby("Vendeur", dropna=False)
    
    contenu_html = "<div style='margin: 15px 0;'>"
    
    for vendeur_unique, groupe_df in groupes:
        contenu_html += f"<h3 style='color: #444;'>Vendeur : {vendeur_unique}</h3>"
        contenu_html += "<ul style='margin-left: 20px;'>"
        
        for _, ligne_groupe in groupe_df.iterrows():
            contenu_html += f"""
            <li style="margin-bottom: 10px;">
                <strong>Titre:</strong> {ligne_groupe.get('Titre ANSSI', 'Non disponible')}<br>
                <strong>Date:</strong> {ligne_groupe.get('Date', 'Non disponible')}<br>
                <strong>Description:</strong> {ligne_groupe.get('Description', 'Non disponible')}<br>
                <strong>Produits Affectés:</strong> {ligne_groupe.get('Produits Affectés', 'Non disponible')}<br>
                <a href="{ligne_groupe.get('Lien', '#')}" target="_blank">Lien vers le détail</a>
            </li>
            """
        contenu_html += "</ul>"
    
    contenu_html += "</div>"
    return contenu_html
def normaliser_vendeur(vendeur):
    if pd.isna(vendeur) or vendeur in ["Non disponible", "Non applicable", ""]:
        return "Vendeur inconnu"
    return vendeur

def generer_email_unique(fichier_csv):
    if not os.path.exists(fichier_csv):
        return "<h2>Le CSV n'existe pas encore, aucun contenu à envoyer.</h2>"

    df_complet = pd.read_csv(fichier_csv)
    df_complet['Date'] = pd.to_datetime(df_complet['Date'], errors='coerce')
    df_alertes = df_complet[df_complet['Type'] == "Alerte"].sort_values(by='Date', ascending=False)
    df_critiques = df_complet[df_complet['Base Severity'] == "Critique"].sort_values(by='Date', ascending=False)
    df_bulletins = df_complet[df_complet['Type'] == "Bulletin d'actualité"].sort_values(by='Date', ascending=False)

    html_final = """
    <html>
    <body style="font-family: Arial, sans-serif;">
      <div style="text-align: center;">
        <!-- Le logo sera inséré via cid:logo_image dans send_email -->
        <img src="cid:logo_image" alt="Logo CERT FR" style="max-width: 150px; margin: 20px auto;" />
      </div>
      <h1 style="text-align: center; color: #007bff;">Rapport CERT FR</h1>
      <p>Veuillez trouver ci-dessous les informations issues de la dernière analyse avec les alertes, puis les avis critiques et enfin les bulletins d'actualité :</p>
    """

    if not df_alertes.empty:
        html_final += "<h2 style='border-top: 1px solid #ccc; padding-top: 10px;'>Alertes</h2>"
        html_final += creer_html_par_vendeur(df_alertes)

    if not df_critiques.empty:
        html_final += "<h2 style='border-top: 1px solid #ccc; padding-top: 10px;'>Avis de sécurité critiques</h2>"
        html_final += creer_html_par_vendeur(df_critiques)

    if not df_bulletins.empty:
        html_final += "<h2 style='border-top: 1px solid #ccc; padding-top: 10px;'>Bulletins d'actualité</h2>"
        html_final += creer_html_bulletins_sans_vendeur(df_bulletins)

    html_final += """
      <p style="margin-top: 30px; font-size: 0.9em; color: #666; text-align: center;">
        © 2025 CERT FR - Tous droits réservés.
      </p>
    </body>
    </html>
    """

    return html_final
def generer_email_contenu_personnalise(df_filtered):
    if df_filtered.empty:
        return "<h2>Aucune donnée disponible pour les vendeurs sélectionnés.</h2>"

    html_final = """
    <html>
    <body style="font-family: Arial, sans-serif;">
      <div style="text-align: center;">
        <img src="cid:logo_image" alt="Logo CERT FR" style="max-width: 150px; margin: 20px auto;" />
      </div>
      <h1 style="text-align: center; color: #007bff;">Rapport personnalisé CERT FR</h1>
      <p>Veuillez trouver ci-dessous les informations filtrées par les vendeurs sélectionnés :</p>
    """

    html_final += creer_html_par_vendeur(df_filtered)

    html_final += """
      <p style="margin-top: 30px; font-size: 0.9em; color: #666; text-align: center;">
        © 2025 CERT FR - Tous droits réservés.
      </p>
    </body>
    </html>
    """

    return html_final

def envoyer_email_html(destinataire, sujet, contenu_html):
    try:
        send_email(destinataire, sujet, contenu_html, from_email, from_mdp, from_nom, chemin_logo)
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email à {destinataire} : {e}")



def envoyer_email_global(fichier_csv, destinataires):
    if not os.path.exists(fichier_csv):
        print("Erreur : Fichier CSV introuvable. Annulation de l'envoi.")
        return

    print(f"Préparation de l'envoi de l'email à {len(destinataires)} destinataire(s)...")
    contenu_html = generer_email_unique(fichier_csv)
    sujet = "Rapport d'information - CERT FR"

    for destinataire_courriel in destinataires:
        # ICI se trouve la correction : on passe explicitement 'chemin_logo'
        # Assurez-vous que 'chemin_logo' est bien défini tout en haut de votre script
        send_email(destinataire_courriel, sujet, contenu_html, from_email, from_mdp, from_nom, chemin_logo)

def send_email(destinataire_courriel, objet, corps_html, expediteur_courriel, mdp_expediteur, nom_expediteur_local="CERT FR", chemin_logo=None, cci=None):
    message = MIMEMultipart("related")
    message['From'] = f"{nom_expediteur_local} <{expediteur_courriel}>"
    message['To'] = destinataire_courriel
    message['Subject'] = objet
    if cci:
        message['Bcc'] = cci

    # Partie HTML
    msg_alternative = MIMEMultipart("alternative")
    message.attach(msg_alternative)
    msg_alternative.attach(MIMEText(corps_html, "html"))

    # Gestion du logo sécurisée
    if chemin_logo and os.path.exists(chemin_logo):
        try:
            with open(chemin_logo, 'rb') as img:
                logo_image = MIMEImage(img.read())
                logo_image.add_header("Content-ID", "<logo_image>")
                message.attach(logo_image)
        except Exception as e:
            print(f"Warning : Impossible d'attacher le logo ({e})")
    else:
        # Si le logo n'est pas là, on ne fait rien (pas de crash)
        pass 

    # Envoi
    try:
        serveur = smtplib.SMTP(serveur_smtp, port_smtp)
        serveur.starttls()
        serveur.login(expediteur_courriel, mdp_expediteur)
        serveur.sendmail(expediteur_courriel, [destinataire_courriel], message.as_string())
        serveur.quit()
        print(f"Email envoyé avec succès à {destinataire_courriel}")
    except Exception as e:
        print(f"Erreur lors de l'envoi SMTP à {destinataire_courriel} : {e}")

###########################################################################
# Lancement global de l'analyse ANSSI (à executer directement sans Django)
###########################################################################

def extraction_rss_enrichissement_cve():
    print("ETAPE 1 : Extraction RSS")
    donnees_rss = extraction_data_rss(urls_rss)
    
    # SECURITE : Si aucune donnée n'est trouvée, on arrête tout de suite
    if donnees_rss.empty:
        print("\n[STOP] Aucune donnée récupérée. Vérifiez votre connexion ou les URLs.")
        return False  # On renvoie False pour dire que ça a échoué

    print("\nETAPE 2 : Recherche des CVE (Parsing HTML)")
    cve_list = []
    # On limite l'affichage pour ne pas spammer la console
    total = len(donnees_rss["Lien"])
    for i, lien in enumerate(donnees_rss["Lien"]):
        print(f"Traitement {i+1}/{total} ...", end="\r")
        cve_list.append(extraction_cve_from_page(lien))
        time.sleep(0.2)
    print("") # Retour à la ligne

    donnees_rss["CVE"] = cve_list

    print("\nETAPE 3 : Enrichissement MITRE")
    enrichir_cve_df(donnees_rss, delay=1)
    
    return True # Tout s'est bien passé

def lancement_global():
    print("\n\n---------- Analyse des Avis et Alertes ANSSI ---------- \n\n")
    
    # On stocke le résultat (True ou False)
    succes = extraction_rss_enrichissement_cve()
    
    # On n'envoie l'email QUE si l'extraction a réussi
    if succes:
        envoyer_email_global(fichier_csv, liste_email)
    else:
        print("Pas d'envoi d'email car l'extraction a échoué.")
        
    print("\n\n---------- Fin de l'analyse ANSSI ---------- \n\n")





    


#####################
# Methode pour Django
#####################

def get_resultat_django(fichier_csv):
    if not os.path.exists(fichier_csv):
        return {
            "total_critiques": "Aucune donnée",
            "total_alertes": "Aucune donnée",
            "total_bulletins": "Aucune donnée",
        }

    df = pd.read_csv(fichier_csv)
    total_critiques = len(df[df["Base Severity"] == "Critique"])
    total_alertes = len(df[df["Type"] == "Alerte"])
    total_bulletins = len(df[df["Type"] == "Bulletin d'actualité"])
    
    return {
        "total_critiques": total_critiques,
        "total_alertes": total_alertes,
        "total_bulletins": total_bulletins,
    }

def lancement_global_django():
    print("\n\n---------- Analyse des Avis et Alertes ANSSI ---------- \n\n")
    print("Tapez dans le terminal la commande suivante : python manage.py runserver")
    print("Puis rendez-vous sur http://127.0.0.1:8000/")









######################################################################################################
# Zone hébergément - Pour une poursuite du projet avec un hébergement web pour pouvoir analyser 24/24
######################################################################################################

def planifier_envoi():
    schedule.every().day.at("20:00").do(lancement_global_django)
    print("Planification active : tous les jours à 20h.\nAppuyez sur CTRL+C pour arrêter.")
    while True:
        schedule.run_pending()
        time.sleep(60)  # On vérifie toutes les 60s


def planifier_test_deux_minutes():
    schedule.every(2).minutes.do(lancement_global_django)
    print("Planification active : toutes les 2 minutes.\nAppuyez sur CTRL+C pour arrêter.")
    while True:
        schedule.run_pending()
        time.sleep(1)  # On vérifie toutes les 1 seconde




##############
# Zone du main
##############
lancement_global()

#extraction_rss_enrichissement_cve()
