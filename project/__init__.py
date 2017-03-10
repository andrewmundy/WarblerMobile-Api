import os
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_bcrypt import Bcrypt
from datetime import timedelta
from flask_cors import CORS

app = Flask(__name__)
bcrypt = Bcrypt(app)

cors = CORS(app, resources={r"/api/*": {"origins": "*"}})
app.config['CORS_HEADERS'] = 'Content-Type'

db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or "postgres://localhost/warbler-api-db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_AUTH_URL_RULE'] = '/api/users/auth'
app.config['SECRET_KEY'] = 'shhhh'
app.config['JWT_EXPIRATION_DELTA'] = timedelta(seconds=3600)
app.config['JWT_DEFAULT_REALM'] = "Login Required"

from project.messages.views import messages_api
from project.users.views import users_api

app.register_blueprint(users_api.blueprint, url_prefix='/api')
app.register_blueprint(messages_api.blueprint, url_prefix='/api/users/<int:user_id>')
