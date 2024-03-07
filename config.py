from flask import Flask
from flask_bootstrap import Bootstrap5
from flask_mail import Mail
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager


app = Flask(__name__)

app.config['SECRET_KEY'] = "dffhlfhlfehvlos.environ.get(flask_key)"
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get("email")
app.config['MAIL_PASSWORD'] = os.environ.get("password")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

Bootstrap5(app)
mail = Mail(app)


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI","sqlite:///Spending.db")
db = SQLAlchemy()
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
