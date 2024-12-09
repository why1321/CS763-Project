import unittest
import sys
sys.path.append("../..")
from flask import request, url_for
from app import app
from app import *
from routes import *
from models import *

class RegistrationTests(unittest.TestCase):

    def setUp(self):
        app.config['TESTING']=True
        app.config['DEBUG']=False
        app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///test.db'
        self.app=app.test_client()
        with app.app_context():S
            db.create_all()

    def tearDown(self):
        with app.app_context():
            db.drop_all()


    def test_registration_page(self):
        response=self.app.get('/register', follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_user_registration(self):
        with self.app as client:
            response = client.post('/register',
                                   data=dict(firstname="testFirstname", lastname="testLastname", username="test",
                                             password="testPassword", email="test@123.com"), follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            user = UserModel.query.filter_by(username="test").first()
            self.assertTrue(user.check_password("testPassword"))

if __name__=="__main__":
    unittest.main()
