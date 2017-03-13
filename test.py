from project import app, db, bcrypt
from project.models import User
from flask_testing import TestCase
from flask import json
import unittest
import jwt

def authenticate(username, password):
    user = User.query.filter(User.username == username).first()
    if bcrypt.check_password_hash(user.password, password):
        token = jwt.encode({'id': user.id}, 'secret', algorithm='HS256').decode('utf-8')
        return token

class BaseTestCase(TestCase):
    def create_app(self):
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///testing.db'
        return app

    def setUp(self):
        db.create_all()
        user1 = User(email='j@rob.edu', username='jrob', image_url='#', password='pass1')
        user2 = User(email='andrew@mundy.gov', username='mundefined', image_url='http://static.djbooth.net/pics-features/jaden-smith.jpg', password='willow')
        user3 = User(email='aaron@manley.com', username='aa-ron', image_url='https://pbs.twimg.com/profile_images/805534047002705925/TDWxrUN8_400x400.jpg', password='iheartsleep')
        db.session.add_all([user1, user2, user3])
        db.session.commit()

    def tearDown(self):
        db.drop_all()

    def _login_user(self):
        return self.client.post('/api/users/auth', content_type='application/json',
        data=json.dumps({
            'username': 'jrob',
            'password': 'pass1'
        })).json

    def test_index(self):
        user_auth = self._login_user()
        response = self.client.get('/api/users',
                    headers={
                    'Authorization':'bearer ' + user_auth['token'],
                    'Content-Type':'application/json'
                    })
        expect_json = [{
            'id': 1,
            'username': 'jrob',
            'image_url': '#',
            'email': 'j@rob.edu',
            'messages': {'id': 0, 'name': None, 'created': None}
        }, {
            'id': 2,
            'username': 'mundefined',
            'image_url': 'http://static.djbooth.net/pics-features/jaden-smith.jpg',
            'email': 'andrew@mundy.gov',
            'messages': {'id': 0, 'name': None, 'created': None}
        }, {
            'id': 3,
            'username': 'aa-ron',
            'image_url': 'https://pbs.twimg.com/profile_images/805534047002705925/TDWxrUN8_400x400.jpg',
            'email': 'aaron@manley.com',
            'messages': {'id': 0, 'name': None, 'created': None}
        }]
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, expect_json)

if __name__ == '__main__':
    unittest.main()
