from flask import Blueprint, abort, request
from flask_restful import Api, Resource, reqparse, marshal_with, fields
from project.models import Message, User
from project import db
import jwt
from flask_jwt import current_identity
from functools import wraps
from jwt.exceptions import DecodeError

messages_api = Api(Blueprint('messages_api', __name__))

def jwt_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.headers.get('token'):
            split_token = request.headers.get('token').split(' ')[2]
        try:
            token = jwt.decode(split_token, 'secret', algorithm='HS256')
            if token:
                return fn(*args, **kwargs)
        except DecodeError as e:
            return abort(401, "Please log in again")
        except UnboundLocalError as e:
            return abort(401, "Please log in again")
        return abort(401, "Please log in")
    return wrapper

def ensure_correct_user(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.headers.get('token'):
            split_token = request.headers.get('token').split(' ')[2]
        try:
            token = jwt.decode(split_token, 'secret', algorithm='HS256')
            if kwargs.get('id') == token.get('id'):
                return fn(*args, **kwargs)
        except DecodeError as e:
            return abort(401, "Please log in again")
        return abort(401, "Unauthorized")
    return wrapper


message_user_fields = {
    'id': fields.Integer,
    'username': fields.String,
}

message_fields= {
    'id': fields.Integer,
    'name': fields.String,
    'created': fields.DateTime(dt_format='rfc822'),
    'user': fields.Nested(message_user_fields)
}

@messages_api.resource('/messages')
class MessagesAPI(Resource):

    @jwt_required
    @marshal_with(message_fields)
    def get(self, user_id):
        return User.query.get_or_404(user_id).messages

    @jwt_required
    @marshal_with(message_fields)
    def post(self, user_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, help='Name')
        args = parser.parse_args()
        new_message = Message(args['name'], user_id)
        db.session.add(new_message)
        db.session.commit()
        print("Adding a message backend")

        return new_message

@messages_api.resource('/messages/<int:id>')
class MessageAPI(Resource):

    @jwt_required
    @marshal_with(message_fields)
    def get(self, user_id, id):
        return Message.query.get_or_404(id)

    @jwt_required
    @marshal_with(message_fields)
    def put(self, user_id, id):
        found_message = Message.query.get_or_404(id)
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, help='Name')
        args = parser.parse_args()
        found_message.name = args['name']
        db.session.add(found_message)
        db.session.commit()

        return found_message

    def delete(self, user_id, id):
        message = Message.query.get_or_404(id)
        db.session.delete(message)
        db.session.commit()
        return None, 204
