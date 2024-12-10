from flask import Flask, jsonify, abort
from flask_login import login_required, current_user, logout_user, login_user
from webargs.flaskparser import parser
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
from models import *
from flask_wtf.csrf import CSRFProtect

# from flask_cors import CORS

# instantiate a Flask application and store that in 'app'
app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# CORS(app)

app.secret_key = os.getenv("APP_SECRET_KEY", "fallback_key")

# config the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../database/data.db'
app.config['SQLALCHEMY_BINDS'] = {'two': 'sqlite:///../database/meal.db'}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Return validation errors via error page
@app.errorhandler(422)
@app.errorhandler(400)
def handle_error(err):
    headers = err.data.get("headers", None)
    messages = err.data.get("messages", ["Invalid request."])
    if headers:
        return jsonify({"h-errors": messages}), err.code, headers
    else:
        return render_template('validationError.html', message=messages)


user = UserModel()
admin = Admin()
db.init_app(app)  # initalize db

from flask import render_template, request, redirect
from models import UserModel, db, login, Admin
from webargs import fields, validate
from usda import extract_avg_calorie_data, usda_api_call, load_cfg

# db.init_app(app)
login.init_app(app)
login.login_view = 'login'



# route for Home Page
@app.route("/")  # home page route
def home():
    return render_template('index.html')




# route for About page
@app.route('/about')  # render about page
def about():
    return render_template('about.html')


@app.route('/foodinput')
@login_required
def user_dashboard():
    return render_template('foodinput.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    msg = ''
    if current_user.is_authenticated:
        return redirect('/foodinput')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = UserModel.query.filter_by(username=username).first()
        if user is not None:
            if user.role == 'customer':
                user = UserModel(user.firstname, user.lastname, user.email, user.username, user.password, user.role)
                path = '/foodinput'
            else:
                user = Admin(user.firstname, user.lastname, user.email, user.username, user.password, user.role)
                path = '/admin/data'
            user = user.check_username_exist(username)
            if user.check_password(password):
                login_user(user)
                session_key = get_random_bytes(16)
                encrypted_token = encrypt_data(user.username, session_key)
                response = redirect('/foodinput')
                response.set_cookie('user_token', encrypted_token, httponly=True, secure=True)
                return response
            else:
                msg = 'Incorrect password!'
        else:
            msg = 'Incorrect username!'

    return render_template('login.html', msg=msg)

def encrypt_data(data, key):
    astc = AESGCM(key)
    nonce = os.urandom(12)  # 12 bytes nonce for AESGCM
    ciphertext = astc.encrypt(nonce, data.encode('utf-8'), None)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_data(encrypted_data, key):
    astc = AESGCM(key)
    decoded_data = base64.b64decode(encrypted_data)
    nonce = decoded_data[:12]
    ciphertext = decoded_data[12:]
    data = astc.decrypt(nonce, ciphertext, None)
    return data.decode('utf-8')
reg_args = {
    "firstname":
        fields.Str(
            validate=validate.Regexp('^[a-zA-Z0-9 ]*$', error='Please do not use special characters'), required=True
        ),
    "lastname":
        fields.Str(
            validate=validate.Regexp('^[a-zA-Z0-9 ]*$', error='Please do not use special characters'), required=True
        ),
    "email": fields.Str(validate=validate.Email(error='Please do not use special characters'), required=True),
    "username":
        fields.Str(
            validate=validate.Regexp('^[a-zA-Z0-9 ]*$', error='Please do not use special characters'), required=True
        ),
    "password":
        fields.Str(validate=validate.Length(min=6, error='Minimum Password length is 6 characters'), required=True)
}


@app.route('/register', methods=['POST', 'GET'])
def register():
    msg = ' '
    role = 'customer'
    if current_user.is_authenticated:
        return redirect('/index')

    if request.method == 'POST':
        # firstname = request.form['firstname']
        # lastname = request.form['lastname']
        # email = request.form['email']
        # username = request.form['username']
        # password = request.form['password']

        args = parser.parse(reg_args, request, location='form')
        firstname = args['firstname']
        lastname = args['lastname']
        email = args['email']
        username = args['username']
        password = args['password']

        customer = UserModel(firstname, lastname, email, username, password, role)
        if customer.check_username_exist(username):
            msg = 'Username is already exist'
            return render_template('register.html', msg=msg)

        if customer.check_email_exist(email):
            msg = 'Email is already exist'
            return render_template('register.html', msg=msg)

        customer.set_password(password)
        if customer.add_user(customer):
            msg = 'User is added successfully!'
            return redirect('/login')
        else:
            msg = 'Failed to add the user!'
    return render_template('register.html', msg=msg)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')


@app.route('/admin/data', methods=['GET', 'POST'])
@login_required
def get_user_data():
    if user.check_admin(current_user.username):
        if request.method == 'GET':
            return render_template('userinput.html')

        if request.method == 'POST':
            username = request.form['username']
            return redirect(f'/admin/data/{username}')
    else:
        return redirect('/')


@app.route('/admin/data/<string:username>', methods=['GET', 'POST'])
@login_required
def display_user_detail(username):
    if user.check_admin(current_user.username):
        user1 = (Admin(user)).retrieve_user(username)
        if user1:
            return render_template('userlist.html', user=user1)
        else:
            return redirect(f'/admin/data')
    else:
        return redirect('/')


@app.route('/admin/data/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update_user_record(id):
    if user.check_admin(current_user.username):
        user1 = UserModel.query.get_or_404(id)
        if request.method == 'POST':
            # user1.firstname = request.form['firstname']
            # user1.lastname = request.form['lastname']
            # user1.username = request.form['username']
            # user1.password = request.form['password']
            # user1.password = user.set_password(user1.password)
            # user1.email = request.form['email']

            args = parser.parse(reg_args, request, location='form')
            user1.firstname = args['firstname']
            user1.lastname = args['lastname']
            user1.email = args['email']
            user1.username = args['username']
            user1.password = args['password']
            user1.password = user.set_password(user1.password)

            try:
                db.session.commit()
                return redirect(f'/admin/data/{user1.username}')
            except exc.SQLAlchemyError:
                return "Problem to updating the user record."
        else:
            return render_template('userupdate.html', user=user1)
    else:
        redirect('/')


@app.route('/admin/data/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_user_record(id):
    if user.check_admin(current_user.username):
        if (Admin(user)).delete_user(id):
            return redirect('/admin/data')
        else:
            return "Problem to deleting the user record."
    else:
        redirect('/')


# dict of input validation tests for foodinput
food_args = {
    "meal_type":
        fields.Str(
            validate=[
                validate.OneOf(['breakfast', 'lunch', 'dinner', 'snack', 'Breakfast', 'Lunch', 'Dinner', 'Snack'],
                               error='Incorrect Meal choice: please select from breakfast, lunch, dinner or snack'),
                validate.Regexp('^[a-zA-Z0-9 ]*$', error='Please do not use special characters')
            ],
            required=True
        ),
    "fitem1":
        fields.Str(
            validate=[
                validate.Length(min=2),
                validate.Regexp('^[a-zA-Z0-9 ]*$', error='Please do not use special characters')
            ],
            required=True
        ),
    "fitem2": fields.Str(validate=validate.Regexp('^[a-zA-Z0-9 ]*$', error='Please do not use special characters'))
}


# route to CREATE a meal entry
@app.route('/foodinput', methods=['POST', 'GET'])  # render food input page
# @login_required
def foodinput():
    # get the data from the form
    if request.method == 'POST':
        # args = parser.load_form(food_args, request)

        args = parser.parse(food_args, request, location='form')

        meal_type = args['meal_type']
        food_item1 = args['fitem1']
        food_item2 = args['fitem2']

        if food_item1 or food_item2:
            try:
                calorie1 = extract_avg_calorie_data(usda_api_call(food_item1, load_cfg()))
            except Exception as e:
                return render_template('foodinput.html', message=e)

            try:
                calorie2 = extract_avg_calorie_data(usda_api_call(food_item2, load_cfg()))
            except Exception as e:
                return render_template('foodinput.html', message=e)
        else:
            return render_template('foodinput.html', message='No foods entered')

        calorie_total = calorie1 + calorie2
        print(calorie_total)
        # use the received data to instantiate a Meal object
        new_meal = MealModel()
        new_meal.meal_type = meal_type
        new_meal.food_item1=food_item1
        new_meal.food_item2=food_item2
        new_meal.calories=calorie_total
        # push the data to the sqlite db
        try:
            db.session.add(new_meal)
            db.session.commit()
            return render_template('foodinput.html', message="Meal Added")

        except:
            return render_template('foodinput.html', message="There was an issue adding your meal details")

    else:
        meals = MealModel.query.order_by(MealModel.date_created).all()
        return render_template('foodinput.html', message="")


@app.route('/foodtable', methods=['GET'])  # render food table page
@login_required
def foodtable():
    # get the data from the form
    try:
        meals = MealModel.query.order_by(MealModel.date_created).all()
        return render_template('foodtable.html', meals=meals)
    except:
        return "There was an issue displaying your meals"


# route to DELETE a meal entry
@app.route('/delete/<int:id>')
@login_required
def delete_meal(id):
    delete_meal = MealModel.query.get_or_404(id)

    try:
        db.session.delete(delete_meal)
        db.session.commit()
        return redirect('/foodtable')

    except:
        return "There was an issue deleting your meal"


# route to UPDATE a meal entry
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update_meal(id):
    meal = MealModel.query.get_or_404(id)

    if request.method == 'POST':

        args = parser.parse(food_args, request, location='form')

        meal.meal_type = args['meal_type']
        meal.food_item1 = args['fitem1']
        meal.food_item2 = args['fitem2']
        try:
            calorie1 = extract_avg_calorie_data(usda_api_call(meal.food_item1, load_cfg()))
            print("Inside food_item1 api calorie call")
        except Exception as e:
            return render_template('foodtable.html', message=e)

        try:
            calorie2 = extract_avg_calorie_data(usda_api_call(meal.food_item2, load_cfg()))
            print("Inside food_item2 api calorie call")
        except Exception as e:
            return render_template('foodtable.html', message=e)

        meal.calories = calorie1 + calorie2
        print(meal.calories)
        try:
            db.session.commit()
            return redirect('/foodtable')

        except:
            return "There was an issue updating your meal"

    else:
        return render_template('update.html', meal=meal)

if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    app.run(debug=debug_mode)
