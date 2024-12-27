from app import db  # Utilisez l'instance `db` depuis `app.py`
from flask_login import UserMixin
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    telephone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    numero = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Haché
    role = db.Column(db.String(20), nullable=False, default='admin')

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
