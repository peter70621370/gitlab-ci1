from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,  BooleanField
from wtforms.validators import DataRequired, Email, Length,  EqualTo, Length, ValidationError
from models import User


#Class Login
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    remember = BooleanField('Se souvenir de moi')
    submit = SubmitField('Se connecter')

#Class Register 
class RegistrationForm(FlaskForm):
    nom = StringField('Nom', validators=[DataRequired(), Length(min=2, max=100)])
    prenom = StringField('Prénom', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    telephone = StringField('Téléphone', validators=[DataRequired(), Length(min=8, max=20)])
    password = PasswordField('Mot de passe', validators=[DataRequired(), Length(min=6, max=100)])
    confirm_password = PasswordField('Confirmez le mot de passe', 
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Créer un compte')

    # Vérification si l'email existe déjà
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Cet email est déjà utilisé. Veuillez en choisir un autre.')