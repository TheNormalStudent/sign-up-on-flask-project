from flask import Blueprint, render_template, request, flash, redirect, url_for
from website_code.models import User, Note
from werkzeug.security import generate_password_hash, check_password_hash
from website_code import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in succesfully!", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password! Try again!', category='error')
        else:
            flash("Such an User does not exist!", category='error') 

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required 
def logout():
    logout_user()
    return render_template("logout.html", user=current_user)

@auth.route('/sign-up', methods = ['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()

        if(user):
            flash("Such a User already exists!", category= 'error')
        elif len(email) < 4:
            flash('Email must be greater than 4 characters', category = "error")
        elif len(name) < 2:
            flash('Name must be greater than 1 characters', category = "error")
        elif password1 != password2:
            flash("Youre password don`t match", category = "error")
        else:
            new_user = User(email = email, first_name = name, password = generate_password_hash(password1, method = 'sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created succesfully', category = "success")    
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)