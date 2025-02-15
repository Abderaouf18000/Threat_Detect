import hashlib
import requests
import zipfile
import os

def download_meta_file(meta_url):
    """
    Télécharge le fichier meta à partir de l'URL spécifiée et retourne les métadonnées sous forme de dictionnaire.
    """
    try:
        response = requests.get(meta_url)
        response.raise_for_status()
        meta_data = {}
        for line in response.text.splitlines():
            key, value = line.strip().split(':', 1)
            meta_data[key.strip()] = value.strip()
        return meta_data
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors du téléchargement du fichier meta : {str(e)}")
        return None

def calculate_file_hash(file_path):
    """
    Calcule le hash SHA-256
    """
    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"Fichier non trouvé : {file_path}")
        return None

def check_for_updates(cve_file_path, meta_url):
    """
    Vérifie si le fichier local doit être mis à jour en comparant le hash local
    """
    # Télécharger et lire les métadonnées du fichier distant
    meta_data = download_meta_file(meta_url)
    if not meta_data:
        return False  # Échec du téléchargement du fichier meta

    # Calculer le hash SHA-256 du fichier local
    local_hash = calculate_file_hash(cve_file_path)
    if not local_hash:
        return True  # Le fichier local n'existe pas, une mise à jour est nécessaire

    remote_hash = meta_data.get("sha256").lower()  # Normalisation en minuscules
    local_hash = local_hash.lower()  # Normalisation en minuscules


    if local_hash == remote_hash:
        print(f"Le fichier local {cve_file_path} est à jour.")
        return False  # Pas besoin de mise à jour
    else:
        print(f"Le fichier distant pour {cve_file_path} a changé. Vous devriez télécharger la nouvelle version.")
        print(f"Hash local : {local_hash}")
        print(f"Hash distant : {remote_hash}")
        return True  # Mise à jour nécessaire

def download_nvd_cve_zip(url, output_file):
    try:
        # Envoyer la requête HTTP pour télécharger le fichier
        response = requests.get(url, stream=True)

        # Vérifier si la requête a réussi
        if response.status_code == 200:
            # Ouvrir un fichier local pour écrire le contenu
            with open(output_file, 'wb') as file:
                for chunk in response.iter_content(chunk_size=1024):
                    file.write(chunk)
            print(f"Téléchargement terminé : {output_file}")
        else:
            print(f"Échec du téléchargement. Statut : {response.status_code}")
    except Exception as e:
        print(f"Une erreur est survenue lors du téléchargement : {str(e)}")

def extract_and_delete_zip_file(zip_file, extract_to):
    try:
        # Vérifier si le fichier ZIP existe
        if os.path.exists(zip_file):
            # Ouvrir et extraire le fichier ZIP
            with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
            print(f"Fichier extrait avec succès dans le dossier : {extract_to}")

            # Supprimer le fichier ZIP après extraction
            os.remove(zip_file)
            print(f"Fichier ZIP supprimé : {zip_file}")
        else:
            print(f"Le fichier ZIP n'existe pas : {zip_file}")
    except Exception as e:
        print(f"Une erreur est survenue lors de l'extraction ou de la suppression : {str(e)}")

# Boucle sur les années de 2002 à 2024
for year in range(2002, 2025):
    # Créer dynamiquement les URLs et chemins de fichiers en fonction de l'année
    meta_url = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.meta'
    cve_file_path = f'1-extracted_cve_data/nvdcve-1.1-{year}.json'

    # URL du fichier ZIP à télécharger
    zip_url = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip'
    # Chemin local où le fichier ZIP sera enregistré
    output_file = f'CVE-{year}.zip'
    # Dossier où le fichier ZIP sera extrait
    extract_to = '1-extracted_cve_data'

    # Vérifier si une mise à jour est nécessaire pour chaque année
    if check_for_updates(cve_file_path, meta_url):
        # Si mise à jour nécessaire, télécharger et extraire le fichier ZIP
        download_nvd_cve_zip(zip_url, output_file)
        extract_and_delete_zip_file(output_file, extract_to)
