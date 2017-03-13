from flask import redirect, request, url_for, Blueprint, abort
from project.models import User
from project import db, bcrypt
from sqlalchemy.exc import IntegrityError
from functools import wraps
from flask_restful import Api, Resource, reqparse, marshal_with, fields
import jwt
from jwt.exceptions import DecodeError

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
            # what is 'secret' for? is that a reference?
            if token:
                # should return GET request on all
                return fn(*args, **kwargs)
        except DecodeError as e:
            return abort(401, "DecodeError, Please log in again")
        except UnboundLocalError as e:
            return abort(401, "UnboundLocalError, Please log in again")
        return abort(401, "Please log in")
    return wrapper

def ensure_correct_user(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):

        if request.headers.get('authorization'):
            split_token = request.headers.get('authorization').split(' ')[1]
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
    'email': fields.String,
    'image_url':fields.String
}


@users_api.resource('/users/auth')
class authAPI(Resource):

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, help='username')
        parser.add_argument('password', type=str, help='password')
        args = parser.parse_args()
        token = authenticate(args['username'], args['password'])
        if token:
            found_user = User.query.filter_by(username= args['username']).first()
            obj = {'token': token, 'id': found_user.id} 
            # this looks like where the JWT token is being returned,
            # and specified to have an id element
            return obj
        return abort(400, "Invalid Credentials")

@users_api.resource('/users')
class usersAPI(Resource):

    @jwt_required
    @marshal_with(user_fields)
    def get(self):
        return User.query.all()


    @marshal_with(user_fields)
    def post(self):

        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, help='username')
        parser.add_argument('password', type=str, help='password')
        parser.add_argument('email', type=str, help='email')
        parser.add_argument('image_url', type=str, help='image_url')
        args = parser.parse_args()


        try:
            new_user = User(username=args['username'], password=args['password'], email=args['email'], image_url=args['image_url'])
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError as e:
            return "Username for API already exists"
        return new_user

@users_api.resource('/users/<int:id>')
class userAPI(Resource):

    @jwt_required
    @ensure_correct_user
    @marshal_with(user_fields)
    def get(self, id):
        return User.query.get_or_404(id)

    @jwt_required
    @ensure_correct_user
    @marshal_with(user_fields)
    def post(self, id):
        # implmeent need to enter passsword to change
        # but already have JWT token, so they already did? Necc?
        found_user = User.query.get(id)
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, help='username')
        parser.add_argument('password', type=str, help='password')
        parser.add_argument('email', type=str, help='email')
        parser.add_argument('image_url', type=str, help='image_url')
        args = parser.parse_args()
        # cant use ['key'], user obj not subscriptable?
        found_user.username = args['username'] or found_user.username
        found_user.email = args['email'] or found_user.email
        found_user.image_url = args['image_url'] or found_user.image_url
        found_user.password = args['password'] or found_user.password
        db.session.add(found_user)
        db.session.commit()
        return found_user






