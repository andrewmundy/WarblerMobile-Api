from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os
from flask import Flask
app = Flask(__name__)

db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or "postgres://localhost/warbler-api-db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or "Warbler Warbler yay! (I'M A SCRET)"

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

from project.users.views import users_api, messages_api

app.register_blueprint(users_api.blueprint, url_prefix='/api')
app.register_blueprint(messages_api.blueprint, url_prefix='/api/users/<int:id>')
