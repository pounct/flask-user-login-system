# -*- coding: utf-8 -*
import os
from flask import Flask,  jsonify, request, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_nav import Nav
from flask_nav.elements import *
from dominate.tags import img
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import secret
from flask_login import UserMixin, LoginManager, login_required, current_user, login_user, logout_user
from forms import LoginForm, RequestResetForm, ResetPasswordForm, SignupForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

#######################################################
#      Define navbar with logo                        #
#######################################################
logo = img(src='./static/img/logo192.png', height="50",
           width="50", style="margin-top:-15px")
# here we define our menu items
nav = Nav()

# registers the "top" menubar
nav.register_element('top', Navbar(logo,
                                   View('Home', 'index'),
                                   View('LogIn', 'login'),
                                   View('SignUp', 'signup'),
                                   #View('Contact', 'contact'),
                                   ))
# registers the "top" menubar
nav.register_element('top2', Navbar(logo,
                                    View('Home', 'index'),
                                    View('Profile', 'profile'),
                                    View('LogOut', 'logout'),
                                    #View('Contact', 'contact'),
                                    ))

app = Flask(__name__)

Bootstrap(app)

app.config['SECRET_KEY'] = secret.secret_key
login_manager = LoginManager(app)
login_manager.login_view = "login"

CORS(app)

# server
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://pounct_root:SamplePass@localhost:3306/pounct_flask01'
# local server
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flask01.db'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:''@localhost/flask01'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# mail server
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = secret.email
app.config['MAIL_PASSWORD'] = secret.pass_email
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)


db = SQLAlchemy(app)

ma = Marshmallow(app)

# it possible create tables as Articles or Products categories etc....
# and create views CRUD for each table...


# class Articles(db.Model):
#    id = db.Column(db.Integer, primary_key=True)
#    title = db.Column(db.String(100))
#    body = db.Column(db.Text())
#    date = db.Column(db.DateTime, default=datetime.datetime.now)
#
#    def __init__(self, title, body):
#        self.title = title
#        self.body = body
#
#
# class ArticleSchema(ma.Schema):
#    class Meta:
#        fields = ('id', 'title', 'body', 'date')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=False)
    email = db.Column(db.String(40), unique=True, nullable=False)
    password = db.Column(db.String(200), primary_key=False,
                         unique=False, nullable=False)
    website = db.Column(db.String(60), index=False,
                        unique=False, nullable=True)
    created_on = db.Column(db.DateTime, index=False,
                           unique=False, nullable=True)
    last_login = db.Column(db.DateTime, index=False,
                           unique=False, nullable=True)
    is_admin = db.Column(db.Boolean, index=False, unique=False)
    #image_file = db.Column(db.String(20), nullable=False, default='default.jpg')

    def set_password(self, password):
        self.password = generate_password_hash(password, method='sha256')

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except Exception as e:
            # print(e)
            return None
        return User.query.get(user_id)

    def __repr__(self):
        # , '{self.image_file}'
        return f"User('{self.name}', '{self.email}')"


#article_schema = ArticleSchema()
#articles_schema = ArticleSchema(many=True)

# you can just create a database as flask01.db
# and you can execute db.create_all() to create all tables
# db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

# sample use a simple api hello world


@app.route('/hello', methods=["GET"])
def hello():
    return jsonify({'Hello': "World"})


@app.route('/login', methods=('GET', 'POST'))
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        # get_user(form.email.data)
        user = User.query.filter_by(email=form.email.data).first()
        if not user or not check_password_hash(user.password, form.password.data):
            flash('Please check your login details and try again.')
            # if the user doesn't exist or password is wrong, reload the page
            return redirect(url_for('login'))
        if user is not None and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            if user.is_admin:
                # create a view for administrador
                return redirect(url_for('index'))
            else:
                return redirect(url_for('profile'))
    return render_template('login.html', form=form)


@app.route('/signup', methods=('GET', 'POST'))
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = SignupForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        website = form.website.data
        is_admin = False  # form.is_admin.data
        # we can remove it from forms and template and create a update view for a super user
        # and only a soper user can update is_admin

        user = User.query.filter_by(email=email).first()
        if user:  # if a user is found, we want to redirect back to signup page so user can try again
            #print('Email address already exists')
            flash('Email address already exists')
            return redirect(url_for('signup'))
        # Creamos el usuario y lo guardamos
        # create a new user with the form data. Hash the password ...
        new_user = User(email=email, name=name,
                        password=generate_password_hash(
                            password, method='sha256'),
                        website=website, is_admin=is_admin)

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        # return redirect(url_for('login'))
        # o Dejamos al usuario logueado:
        login_user(new_user, remember=False)
        if user.is_admin:
            # create a view for administrador
            # redirect(url_for('profile_admin'))
            return redirect(url_for('index'))
        else:
            return redirect(url_for('profile'))
    return render_template("signup.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)


@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender=secret.email,
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            flash('There is no account with that email. You must register first.')
            return redirect(url_for('reset_request'))
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot.html', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(
            form.password.data, method='sha256')
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


nav.init_app(app)

if __name__ == "__main__":
    app.run(debug=True)
