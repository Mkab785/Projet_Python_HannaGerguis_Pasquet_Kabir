from django.shortcuts import render
import pandas as pd
import os
import csv
from .Projet_Django_ANSSI import extraction_rss_enrichissement_cve, envoyer_email_global
from .Projet_Django_ANSSI import envoyer_email_html, generer_email_contenu_personnalise

fichier_csv = os.path.join(os.path.dirname(__file__), 'tous_les_cve.csv')
global_vendors = []

def charger_donnees_csv():
    if os.path.exists(fichier_csv):
        donnees = pd.read_csv(fichier_csv)
        critiques = donnees[donnees['Base Severity'] == "Critique"]
        alertes = donnees[donnees['Type'] == "Alerte"]
        bulletins = donnees[donnees['Type'] == "Bulletin d'actualité"]
        vendeur = donnees['Type'] == "Vendeur"
        return {
            "critiques": len(critiques),
            "alertes": len(alertes),
            "bulletins": len(bulletins),
            "vendeur": len(vendeur),
        }
    return {"critiques": 0, "alertes": 0, "bulletins": 0}


def page_principale(request):
    return render(request, "analyse/page_principale.html")



def afficher_resultats(request):
    donnees = charger_donnees_csv()
    global_vendors = []
    with open(fichier_csv, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        global_vendors = sorted(
            set(row['Vendeur'] for row in reader if 'Vendeur' in row and row['Vendeur'] not in ["Non disponible", "Non applicable", ""])
        )
    print("Vendors trouvés :", global_vendors)  # Debug

    total_critiques = donnees.get("critiques", 0)
    total_alertes = donnees.get("alertes", 0)
    total_bulletins = donnees.get("bulletins", 0)

    message = None

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "send_email":
            email = request.POST.get("email")
            if email:
                selected_vendors = request.POST.getlist('selected_vendors')
                envoyer_email_vendeur(email, selected_vendors) 
        elif action == "refresh_data":
            extraction_rss_enrichissement_cve()

    return render(request, "analyse/resultats.html", {
        "total_critiques": total_critiques,
        "total_alertes": total_alertes,
        "total_bulletins": total_bulletins,
        "message": message,
        "vendors": global_vendors,  
    })


def afficher_jupyter_notebook(request):
    return render(request, "analyse/jupyter_notebook.html")


def afficher_informations(request):
    return render(request, 'analyse/informations.html')


def envoyer_email_vendeur(email, selected_vendors):
    if not os.path.exists(fichier_csv):
        print("Erreur : Fichier CSV introuvable.")
        return

    if not selected_vendors:  # Si aucun vendeur n'est sélectionné
        print("Aucun vendeur sélectionné, envoi de toute la data.")
        df_data = pd.read_csv(fichier_csv)  # Charger tout le fichier CSV
    else:
        # Filtrer les données par vendeurs
        filtered_data = []
        with open(fichier_csv, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row['Vendeur'] in selected_vendors:
                    filtered_data.append(row)
        
        if not filtered_data:
            print("Aucune donnée trouvée pour les vendeurs sélectionnés.")
            return

        df_data = pd.DataFrame(filtered_data)  # Convertir en DataFrame

    # Générer le contenu HTML pour l'email
    contenu_html = generer_email_contenu_personnalise(df_data)
    sujet = "Rapport personnalisé - CERT FR"
    envoyer_email_html(email, sujet, contenu_html)
    print(f"Email envoyé à {email} avec les données sélectionnées.")



