import requests
import uuid
import os
import pandas as pd
import json
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_paginate import Pagination, get_page_args
from collections import defaultdict



app = Flask(__name__)

# Clés API pour l'API SMS NGHCorp
API_SMS_KEY = 'k_2uVvLvbdVgKdoObnzwgeOb1QLMYoIOY6'
API_SMS_SECRET = 's_U7rk8A_IwcTC8Q8ASb06wVi9WyXzKfYk'
SMS_API_URL = 'https://extranet.nghcorp.net/api/send-sms'

# Clé secrète pour les sessions Flask
app.config['SECRET_KEY'] = 'c8fca16e7ced0717371b8dd45cd6185a'

# Configuration de MySQL
app.config['MYSQL_HOST'] = 'mysql-service'
app.config['MYSQL_USER'] = 'user'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'sp_wi'

# Initialiser MySQL et bcrypt
mysql = MySQL(app)
bcrypt = Bcrypt(app)



SEUIL_IDENTIFIANTS = 10  # Exemple : alerte lorsque le nombre d'identifiants est inférieur à 10

# Charger le fichier CSV des login/mots de passe
csv_file_path = os.path.join(os.path.dirname(__file__), 'data', 'passwords.csv')
passwords_df = pd.read_csv(csv_file_path)

# Charger le fichier CSV
try:
    passwords_df = pd.read_csv(csv_file_path)
    print(f"Fichier CSV chargé avec succès :\n{passwords_df.head()}")
except FileNotFoundError:
    print(f"Le fichier passwords.csv n'a pas été trouvé au chemin : {csv_file_path}")
except Exception as e:
    print(f"Erreur lors du chargement du fichier CSV : {e}")

# URL et clé API pour PayGate
PAYGATE_URL = 'https://paygateglobal.com/api/v1/pay'
API_KEY = 'a81d1e51-bf4c-4fa1-ad94-ef30eb442c58'

@app.route('/')
def index():
    return render_template('index.html')

def get_login_and_password_for_amount(df, amount):
    """
    Cette fonction récupère un login et un mot de passe en fonction du montant payé.
    100F -> 3H, 200F -> 24H, 500F -> 7J
    """
    # Logique basée sur le montant
    if amount == 1:
        # Filtrer pour 3 heures (3H)
        available_entries = df[df['Uptime Limit'] == '3h']
    elif amount == 2:
        # Filtrer pour 1 jour (24H)
        available_entries = df[df['Uptime Limit'] == '1d']
    elif amount == 5:
        # Filtrer pour 7 jours (7d) - ajouter ces entrées si elles existent
        available_entries = df[df['Uptime Limit'] == '7d']
    else:
        # Si le montant ne correspond à aucun plan
        return None, None

    # Récupérer le premier login et mot de passe disponibles
    if not available_entries.empty:
        first_entry = available_entries.iloc[0]
        login = first_entry['Login']
        password = first_entry['Password']

        # Supprimer cette ligne pour marquer le login et le mot de passe comme utilisés
        df = df.drop(available_entries.index[0])
        df.to_csv(csv_file_path, index=False)  # Écraser le fichier CSV avec la ligne supprimée

        return login, password
    else:
        return None, None

def format_phone_number(phone_number):
    # Si le numéro n'a pas d'indicatif international, on ajoute l'indicatif du Togo (+228)
    if not phone_number.startswith('+'):
        return f'+228{phone_number[-8:]}'  # On s'assure d'envoyer le numéro au format +228XXXXXXX
    return phone_number


def send_sms(phone_number, login, password):
    # Formater le numéro de téléphone
    phone_number = format_phone_number(phone_number)

    # Message à envoyer
    sms_message = f"Votre login: {login} et mot de passe: {password} pour accès Wi-Fi."
    
    # Préparer le payload pour NGHCorp
    payload = {
        'from': 'WASHMAN',  # Remplace par ton identifiant d'expéditeur validé
        'to': phone_number,
        'text': sms_message,
        'reference': str(uuid.uuid4()),  # Un identifiant unique pour le SMS
        'api_key': API_SMS_KEY,
        'api_secret': API_SMS_SECRET
    }

    headers = {
        'Content-Type': 'application/json'
    }

    try:
        # Utiliser json=payload pour envoyer un JSON correctement formaté
        response = requests.post(SMS_API_URL, json=payload, headers=headers)

        # Log de la réponse de l'API
        print(f"Réponse de l'API SMS NGHCorp: {response.status_code}, {response.text}")
        
        # Retourner True si le SMS est envoyé avec succès
        if response.status_code == 200:
            return True
        else:
            print(f"Erreur lors de l'envoi du SMS: {response.status_code}, {response.json()}")
            return False
    except Exception as e:
        print(f"Erreur lors de la connexion à l'API NGHCorp : {e}")
        return False



# Détecter le type de réseau
def detect_network(phone_number):
    # Liste de préfixes des numéros Moov (Flooz)
    moov_prefixes = ['96', '97', '98', '99', '79']
    
    # Liste de préfixes des numéros Togocom (TMoney)
    togocom_prefixes = ['70', '71', '90', '91', '92', '93']

    if phone_number.startswith(tuple(moov_prefixes)):
        return 'FLOOZ'
    elif phone_number.startswith(tuple(togocom_prefixes)):
        return 'TMONEY'
    else:
        return None  # Retourne None si le réseau n'est pas reconnu

@app.route('/payer', methods=['POST'])
def payer():
    phone_number = request.form['phone_number']
    tarif = float(request.form['tarif'])  # Assure que le tarif est bien un nombre

    # Détecter automatiquement le réseau en fonction du numéro
    network = detect_network(phone_number)

    print(f'Numéro: {phone_number}, Réseau détecté: {network}')

    if not network:
        flash('Le réseau du numéro n\'est pas reconnu. Veuillez vérifier le numéro.')
        return redirect(url_for('index'))

    # Générer un identifiant unique pour cette transaction
    identifier = str(uuid.uuid4())

    # Préparer les données à envoyer à PayGate
    payload = {
        'auth_token': API_KEY,
        'phone_number': phone_number,
        'amount': tarif,
        'description': 'Paiement pour accès Wi-Fi',
        'identifier': identifier,
        'network': network
    }

    try:
        # Faire la requête à PayGate pour initier le paiement
        response = requests.post(PAYGATE_URL, json=payload)
        response_data = response.json()

        print(f"Réponse de PayGate: {response.status_code}, {response_data}")

        # Si la requête à PayGate réussit, rediriger vers une page de confirmation
        if response.status_code == 200 and response_data.get('status') == 0:
            flash('Paiement initié avec succès! Veuillez attendre la confirmation du paiement.', 'info')
            return redirect(url_for('index'))
        else:
            flash(f'Erreur lors de l\'enregistrement du paiement : {response_data.get("message", "Erreur inconnue")}')
            return redirect(url_for('index'))

    except Exception as e:
        flash(f'Erreur de connexion au service de paiement : {e}')
        print(f"Erreur de connexion à PayGate: {e}")
        return redirect(url_for('index'))



@app.route('/confirmation_paygate', methods=['POST'])
def confirmation_paygate():
    # Recevoir les données de confirmation de PayGate
    data = request.get_json()
    print(f"Données reçues de PayGate: {data}")
    
    # Extraire les informations envoyées par PayGate
    tx_reference = data.get('tx_reference')
    phone_number = data.get('phone_number')
    amount = float(data.get('amount')) if 'amount' in data else None
    
    if tx_reference and phone_number:
        print(f"Paiement confirmé par PayGate pour {phone_number}.")
        
        # Récupérer les identifiants en fonction du montant payé
        login, password = get_login_and_password_for_amount(passwords_df, amount)
        
        if login and password:
            # Enregistrer la vente dans la base de données
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO tickets_vendus (login, password, montant, phone_number) VALUES (%s, %s, %s, %s)",
                        (login, password, amount, phone_number))
            mysql.connection.commit()
            
            # Ajouter une notification pour l'admin
            message = f'Un nouveau ticket de {amount} FCFA a été vendu.'
            cur.execute("INSERT INTO notifications (message, date, is_read) VALUES (%s, NOW(), %s)", (message, False))
            mysql.connection.commit()

            cur.close()

            # Envoyer les identifiants par SMS
            if send_sms(phone_number, login, password):
                print(f"SMS envoyé à {phone_number} avec Identifiant: {login} et Mot de passe: {password}.")
                return "Paiement confirmé et SMS envoyé", 200
            else:
                print(f"Erreur lors de l'envoi du SMS à {phone_number}.")
                return "Erreur lors de l'envoi du SMS", 500
        else:
            print(f"Aucun identifiant disponible pour {phone_number}.")
            return "Aucun identifiant disponible", 400
    else:
        print("Échec du paiement ou information manquante.")
        return "Paiement échoué", 400







@app.route('/verifier_etat', methods=['POST'])
def verifier_etat():
    identifier = request.form['identifier']  # Identifiant de la transaction

    payload = {
        'auth_token': API_KEY,
        'identifier': identifier
    }

    response = requests.post('https://paygateglobal.com/api/v2/status', json=payload)
    response_data = response.json()

    print(f"Réponse de l'état de la transaction de PayGate: {response.status_code}, {response_data}")

    if response.status_code == 200 and response_data.get('status') == 0:
        return f"Paiement réussi pour {response_data['amount']} FCFA"
    else:
        return "État du paiement : " + response_data.get('status')
    

    

#Routes admin

# Route d'inscription
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nom = request.form['nom']
        prenom = request.form['prenom']
        email = request.form['email']
        telephone = request.form['telephone']
        password = request.form['password']
        repeat_password = request.form['repeat_password']
        
        if password != repeat_password:
            flash('Les mots de passe ne correspondent pas', 'danger')
            return redirect(url_for('register'))

        # Hacher le mot de passe
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Vérification si l'email existe déjà
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            flash('Cet email est déjà utilisé.', 'danger')
            return redirect(url_for('register'))

        # Insertion des données dans la base de données
        cur.execute("INSERT INTO users (nom, prenom, email, telephone, password) VALUES (%s, %s, %s, %s, %s)", 
                    (nom, prenom, email, telephone, hashed_password))
        mysql.connection.commit()
        cur.close()
        
        flash('Compte créé avec succès! Vous pouvez maintenant vous connecter.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Route de connexion
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Vérification des identifiants
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        
        if user and bcrypt.check_password_hash(user[5], password):  # 5 correspond à la colonne password
            session['loggedin'] = True
            session['id'] = user[0]
            session['nom'] = user[1]
            session['role'] = user[6]  # Stocker le rôle dans la session (superadmin ou admin)
            flash('Connexion réussie!', 'success')
            return redirect(url_for('admin'))
        else:
            flash('Échec de la connexion. Vérifiez vos identifiants.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('login'))

# Route d'administration (nécessite une connexion)
from datetime import datetime, timedelta

@app.route('/admin')
def admin():
    if 'loggedin' in session:
        try:
            # Charger les identifiants depuis le fichier CSV
            csv_file_path = os.path.join(app.root_path, 'data', 'passwords.csv')
            passwords_df = pd.read_csv(csv_file_path)

            seuil_identifiants = 10

            # Filtrer par montant ou durée
            ident_100F = passwords_df[passwords_df['Uptime Limit'] == '3h']
            ident_200F = passwords_df[passwords_df['Uptime Limit'] == '1d']
            ident_500F = passwords_df[passwords_df['Uptime Limit'] == '7d']

            # Compter le nombre d'identifiants pour chaque catégorie
            nb_ident_100F = len(ident_100F)
            nb_ident_200F = len(ident_200F)
            nb_ident_500F = len(ident_500F)
            total_tickets = nb_ident_100F + nb_ident_200F + nb_ident_500F

            cur = mysql.connection.cursor()

            # Ventes totales
            cur.execute("SELECT COUNT(*) FROM tickets_vendus")
            total_sales = cur.fetchone()[0]

            # Ventes du jour
            cur.execute("""
                SELECT COUNT(*) FROM tickets_vendus
                WHERE DATE(date_achat) = CURDATE()
            """)
            daily_sales = cur.fetchone()[0]

            # Nombre total d'utilisateurs
            cur.execute("SELECT COUNT(*) FROM users")
            total_users = cur.fetchone()[0]

            # Récupérer les ventes mensuelles
            cur.execute("""
                SELECT MONTH(date_achat) AS month, COUNT(*) AS sales_count
                FROM tickets_vendus
                WHERE YEAR(date_achat) = YEAR(CURDATE())
                GROUP BY MONTH(date_achat)
                ORDER BY MONTH(date_achat)
            """)
            monthly_sales = cur.fetchall()

            # Préparer les données pour le graphique (12 mois, initialisé à 0)
            sales_data = {i: 0 for i in range(1, 13)}  # 12 mois de l'année
            for row in monthly_sales:
                month = row[0]  # Indice 0 correspond au mois
                sales_count = row[1]  # Indice 1 correspond au nombre de ventes
                sales_data[month] = sales_count

            # Assurez-vous que sales_by_month contient bien 12 valeurs
            sales_by_month = [sales_data[i] for i in range(1, 13)]

            # Debugging: print sales_by_month pour vérifier
            print(f"Sales by month: {sales_by_month}")

            cur.close()

            return render_template('admin.html',
                                   nb_ident_100F=nb_ident_100F,
                                   nb_ident_200F=nb_ident_200F,
                                   nb_ident_500F=nb_ident_500F,
                                   sales_by_month=sales_by_month,
                                   daily_sales=daily_sales,  # Ajouté
                                   total_sales=total_sales,  # Ajouté
                                   total_users=total_users,  # Ajouté
                                   total_tickets=total_tickets  # Ajouté
                                   )
        except FileNotFoundError:
            flash('Le fichier des identifiants n\'a pas été trouvé.', 'danger')
            return render_template('admin.html')
        except Exception as e:
            flash(f'Erreur lors du chargement des données : {e}', 'danger')
            return render_template('admin.html')
    else:
        flash('Veuillez vous connecter pour accéder à cette page.', 'danger')
        return redirect(url_for('login'))



@app.route('/create_admin', methods=['GET', 'POST'])
def create_admin():
    if 'loggedin' in session and session.get('role') == 'superadmin':
        if request.method == 'POST':
            # Récupérer tous les champs du formulaire
            nom = request.form['nom']
            prenom = request.form['prenom']
            email = request.form['email']
            telephone = request.form['telephone']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            role = request.form['role']  # admin ou superadmin
            
            # Vérifier que les mots de passe correspondent
            if password != confirm_password:
                flash('Les mots de passe ne correspondent pas', 'danger')
                return redirect(url_for('create_admin'))
            
            # Hacher le mot de passe
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            # Vérifier si l'email existe déjà
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            
            if user:
                flash('Cet email est déjà utilisé.', 'danger')
                return redirect(url_for('create_admin'))

            # Insertion dans la base de données avec tous les champs
            cur.execute("""
                INSERT INTO users (nom, prenom, email, telephone, password, role) 
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (nom, prenom, email, telephone, hashed_password, role))
            mysql.connection.commit()
            cur.close()
            
            flash(f'Compte {role} créé avec succès!', 'success')
            return redirect(url_for('admin'))
        
        return render_template('create_admin.html')  # Formulaire pour créer un admin
    else:
        flash('Vous n\'avez pas la permission de créer des comptes admin.', 'danger')
        return redirect(url_for('admin'))


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'loggedin' in session:
        if request.method == 'POST':
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_new_password = request.form['confirm_new_password']
            
            # Vérifier si les nouveaux mots de passe correspondent
            if new_password != confirm_new_password:
                flash('Les mots de passe ne correspondent pas', 'danger')
                return redirect(url_for('change_password'))
            
            # Vérifier si le mot de passe actuel est correct
            cur = mysql.connection.cursor()
            cur.execute("SELECT password FROM users WHERE id = %s", (session['id'],))
            user = cur.fetchone()
            cur.close()
            
            if not bcrypt.check_password_hash(user[0], current_password):
                flash('Le mot de passe actuel est incorrect.', 'danger')
                return redirect(url_for('change_password'))
            
            # Hacher le nouveau mot de passe
            hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            
            # Mettre à jour le mot de passe dans la base de données
            cur = mysql.connection.cursor()
            cur.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_new_password, session['id']))
            mysql.connection.commit()
            cur.close()
            
            flash('Votre mot de passe a été mis à jour avec succès!', 'success')
            return redirect(url_for('admin'))
        
        return render_template('change_password.html')
    else:
        flash('Veuillez vous connecter pour modifier votre mot de passe.', 'danger')
        return redirect(url_for('login'))


@app.route('/user_list')
def user_list():
    # Récupérer tous les utilisateurs de la base de données
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nom, prenom, email, telephone, role FROM users")
    users = cur.fetchall()
    cur.close()

    # Rendre le template et passer la liste des utilisateurs
    return render_template('user_list.html', users=users)

@app.route('/create_user')
def create_user():
    return render_template('create_user.html') 

@app.route('/tickets_vendus')
def tickets_vendus():
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        cur.execute("SELECT login, password, montant, phone_number, date_achat FROM tickets_vendus ORDER BY date_achat DESC")
        tickets = cur.fetchall()
        cur.close()
        return render_template('tickets_vendus.html', tickets=tickets)
    else:
        flash('Veuillez vous connecter pour accéder à cette page.', 'danger')
        return redirect(url_for('login'))
  

@app.route('/charger_ident', methods=['GET', 'POST'])
def charger_ident():
    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename.endswith('.csv'):
            # Sauvegarder le fichier dans le répertoire data
            file_path = os.path.join(app.root_path, 'data', 'passwords.csv')
            file.save(file_path)

            # Traitement du fichier CSV après upload
            try:
                passwords_df = pd.read_csv(file_path)
                flash('Fichier CSV chargé et traité avec succès.', 'success')
            except Exception as e:
                flash(f'Erreur lors du traitement du fichier CSV : {e}', 'danger')
        else:
            flash('Veuillez télécharger un fichier CSV valide.', 'danger')
        return redirect(url_for('charger_ident'))

    return render_template('charger_ident.html')
    

@app.route('/ident_list')
def ident_list():
    # Récupérer le tarif (prix) sélectionné par l'utilisateur
    tarif = request.args.get('tarif')
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page', default=10)

    try:
        # Charger les identifiants à partir du fichier CSV
        csv_file_path = os.path.join(app.root_path, 'data', 'passwords.csv')
        passwords_df = pd.read_csv(csv_file_path)

        # Filtrer les identifiants par prix si un tarif est spécifié
        if tarif:
            if tarif == '100':
                passwords_df = passwords_df[passwords_df['Uptime Limit'] == '3h']
            elif tarif == '200':
                passwords_df = passwords_df[passwords_df['Uptime Limit'] == '1d']
            elif tarif == '500':
                passwords_df = passwords_df[passwords_df['Uptime Limit'] == '7d']

        # Convertir le DataFrame en une liste de dictionnaires pour utilisation dans Jinja2
        identifiants = passwords_df.to_dict(orient='records')

        # Vérification s'il y a des identifiants disponibles
        if len(identifiants) == 0:
            flash('Aucun identifiant disponible pour le moment.', 'warning')

        # Gestion de la pagination
        total = len(identifiants)
        pagination_identifiants = identifiants[offset:offset + per_page]
        pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

        return render_template('ident_list.html', identifiants=pagination_identifiants, pagination=pagination, filtre_tarif=tarif)

    except FileNotFoundError:
        flash('Le fichier CSV des identifiants n\'a pas été trouvé.', 'danger')
        return render_template('ident_list.html', identifiants=[], pagination=None)

    except Exception as e:
        flash(f'Erreur lors du chargement des identifiants : {e}', 'danger')
        return render_template('ident_list.html', identifiants=[], pagination=None)
    
    
@app.route('/notifications', methods=['GET'])
def notifications():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, message, date FROM notifications WHERE is_read = 0")
    notifications = cur.fetchall()
    cur.close()

    return jsonify(notifications=[{
        'id': notification[0],
        'message': notification[1],
        'date': notification[2]
    } for notification in notifications])


@app.route('/mark_as_read/<int:notification_id>', methods=['GET'])
def mark_as_read(notification_id):
    try:
        # Mettre à jour l'état de la notification comme lue dans la base de données
        cur = mysql.connection.cursor()
        cur.execute("UPDATE notifications SET is_read = 1 WHERE id = %s", (notification_id,))
        mysql.connection.commit()
        cur.close()
        flash('Notification marquée comme lue.', 'success')
    except Exception as e:
        flash(f'Erreur lors de la mise à jour de la notification : {e}', 'danger')
    return redirect(url_for('admin'))


    
if __name__ == '__main__':
    app.run(debug=True)
