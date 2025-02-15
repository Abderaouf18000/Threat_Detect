import requests
import json

# Configuration de l'API
BASE_URL = "http://192.168.2.83:49090/1"
API_KEY = "fing_loc_api123"

def fetch_data_from_fing(endpoint):
    """
    Récupère les données depuis un endpoint Fing.
    :param endpoint: Endpoint de Fing ('devices' ou 'people')
    :return: Données JSON de la réponse ou None si une erreur survient
    """
    url = f"{BASE_URL}/{endpoint}?auth={API_KEY}"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Vérifie que la requête est réussie
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération des données depuis {url} : {e}")
        return None

def save_json(data, filename):
    """
    Sauvegarde les données JSON dans un fichier local.
    :param data: Données JSON à sauvegarder
    :param filename: Nom du fichier
    """
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=4, ensure_ascii=False)
        print(f"Les données ont été sauvegardées dans {filename}.")
    except IOError as e:
        print(f"Erreur lors de la sauvegarde des données : {e}")

def main():
    # Récupération des appareils détectés
    devices = fetch_data_from_fing("devices")
    if devices:
        print("Appareils détectés :")
        for device in devices.get("devices", []):
            print(f"- {device.get('name', 'Inconnu')} ({device.get('ip', ['Aucune IP'])[0]})")
        save_json(devices, "devices.json")



if __name__ == "__main__":
    main()
