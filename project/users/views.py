from flask import redirect, request, url_for, Blueprint
from project.models import User
from project import db, bcrypt
from sqlalchemy.exc import IntegrityError
from functools import wraps
from flask_restful import Api, Resource, reqparse, marshal_with, fields

# cped over code
def authenticate(username, password):
    user = User.query.filter(User.username == username).first()
    if bcrypt.check_password_hash(user.password, password):
        token = jwt.encode({'id': user.id}, 'secret', algorithm='HS256').decode('utf-8')
        return token

def jwt_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.headers.get('authorization'):
            split_token = request.headers.get('authorization').split(' ')[1]
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

        if request.headers.get('authorization'):
            split_token = request.headers.get('authorization').split(' ')[2]
        try:
            token = jwt.decode(split_token, 'secret', algorithm='HS256')
            if kwargs.get('id') == token.get('id'):
                return fn(*args, **kwargs)
        except DecodeError as e:
            return abort(401, "Please log in again")
        return abort(401, "Unauthorized")
    return wrapper

# CPed over code

users_blueprint = Blueprint(
  'users',
  __name__,
  template_folder='templates'
)

messages_blueprint = Blueprint(
  'messages',
  __name__,
  template_folder='templates'
)

users_api = Api(Blueprint('users_api', __name__))
messages_api = Api(Blueprint('messages_api', __name__))

user_fields= {
    'id': fields.Integer,
    'username': fields.String,
}

@users_api.resource('/users')
class usersAPI(Resource):

    # @jwt_required
    @marshal_with(user_fields)
    def get(self):
        return User.query.all()

    @marshal_with(user_fields)
    def post(self):

        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, help='username')
        parser.add_argument('password', type=str, help='password')
        args = parser.parse_args()

        try:
            new_user = User(args['username'], args['password'])
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError as e:
            return "Username for API already exists"
        return new_user


  