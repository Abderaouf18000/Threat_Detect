import json
import mysql.connector
import os
import logging
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename='cve_import.log', filemode='w')

# Connexion à la base de données MySQL avec gestion des erreurs
try:
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Root@1234",
        database="vulnerabilities_db"
    )
    cursor = db.cursor()
    logging.info("Connexion à la base de données réussie.")
except mysql.connector.Error as err:
    logging.error(f"Erreur de connexion à la base de données : {err}")
    exit(1)

# Fonction pour extraire les informations CVE et les insérer dans la base de données
def insert_cve_data(cve_item):
    try:
        cve_id = cve_item['cve']['CVE_data_meta']['ID']
        description = cve_item['cve']['description']['description_data'][0]['value']

        # Récupérer les scores CVSS si disponibles
        cvss_v2_score = cvss_v2_vector = None
        if 'baseMetricV2' in cve_item.get('impact', {}):
            cvss_v2_score = cve_item['impact']['baseMetricV2']['cvssV2']['baseScore']
            cvss_v2_vector = cve_item['impact']['baseMetricV2']['cvssV2']['vectorString']

        cvss_v3_score = cvss_v3_vector = None
        if 'baseMetricV3' in cve_item.get('impact', {}):
            cvss_v3_score = cve_item['impact']['baseMetricV3']['cvssV3']['baseScore']
            cvss_v3_vector = cve_item['impact']['baseMetricV3']['cvssV3']['vectorString']

        # Dates
        created_at = cve_item['publishedDate']
        last_modified_at = cve_item['lastModifiedDate']

        # Filtrer les CVE en fonction des années
        year = datetime.strptime(created_at, "%Y-%m-%dT%H:%MZ").year
        if year < 2018 or year > 2024:
            return

        # Insertion dans la base de données
        sql = """
        INSERT INTO vulnerabilities (cve_id, description, cvss_v2_score, cvss_v2_vector, cvss_v3_score, cvss_v3_vector, vuln_status, created_at, last_modified_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            cve_id, description,
            cvss_v2_score, cvss_v2_vector,
            cvss_v3_score, cvss_v3_vector,
            'Non rectifiée', created_at, last_modified_at
        )

        cursor.execute(sql, values)
        db.commit()
        logging.info(f"CVE {cve_id} insérée avec succès.")

    except Exception as e:
        logging.error(f"Erreur lors de l'insertion des données CVE {cve_id} : {e}")

# Dossier contenant les fichiers JSON
json_folder = "1-extracted_cve_data"

# Parcourir les fichiers JSON de 2018 à 2024
for year in range(2008, 2025):
    json_file = f'nvdcve-1.1-{year}.json'
    file_path = os.path.join(json_folder, json_file)

    if os.path.exists(file_path):
        try:
            with open(file_path, encoding='utf-8') as file:
                data = json.load(file)

            # Parcourir les CVE et insérer les données
            for item in data['CVE_Items']:
                insert_cve_data(item)

            logging.info(f"Insertion des données du fichier {json_file} terminée avec succès.")
        except json.JSONDecodeError as e:
            logging.error(f"Erreur de décodage JSON dans le fichier {json_file} : {e}")
    else:
        logging.warning(f"Le fichier {json_file} n'existe pas dans le dossier {json_folder}.")

# Fermer la connexion
cursor.close()
db.close()
logging.info("Traitement de tous les fichiers terminé avec succès.")
