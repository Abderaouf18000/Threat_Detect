import mysql.connector

def vider_table(database_name, table_name):
    try:
        # Connexion à la base de données
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Root@1234",
            database=database_name
        )
        cursor = conn.cursor()

        # Requête SQL pour vider la table
        query = f"TRUNCATE TABLE {table_name};"
        cursor.execute(query)

        # Confirmation de la suppression
        conn.commit()

        print(f"La table '{table_name}' a été vidée avec succès.")

    except mysql.connector.Error as err:
        print(f"Erreur: {err}")

    finally:
        # Fermeture de la connexion
        if conn.is_connected():
            cursor.close()
            conn.close()
            print("La connexion à la base de données a été fermée.")

#vider_table('vulnerabilities_db', 'cpe_data')
vider_table('vulnerabilities_db', 'vulnerabilities')
