from datetime import datetime
from project import db, bcrypt

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True)
    password = db.Column(db.Text)
    messages = db.relationship('Model', backref='user', lazy='joined')
    created = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self,username, password):
        self.username = username
        self.password = bcrypt.generate_password_hash(password).decode('UTF-8')

    def __repr__(self):
        return "Name: {}, ID: {}, Messages: {}, Created: {}".format(self.username,self.id, self.messages, self.created)

class Message(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self,name, user_id):
        self.name = name
        self.user_id = user_id

    def __repr__(self):
        return "Name: {}, ID: {}".format(self.name,self.user_id)
