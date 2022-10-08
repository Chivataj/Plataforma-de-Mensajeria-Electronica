import functools
import random
import flask
from . import utils

from email.message import EmailMessage
import smtplib

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/activate', methods=('GET', 'POST'))
def activate():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == "GET":
            number = request.args['auth']

            db = get_db() 
            attempt = db.execute( # Guarda en la variable attemp los datos de la tabla activationlink que tengan el number del link y el state unconfirmed 
                "SELECT * FROM activationlink WHERE challenge = ? AND state = ?", (number, utils.U_UNCONFIRMED)
            ).fetchone()

            if attempt is not None: # Actualiza el state a confirmed
                db.execute(
                    "UPDATE activationlink SET state = ? WHERE id = ?", (utils.U_CONFIRMED, attempt['id'])
                )
                db.execute( # Agrega los datos a la tabla usuario y asi activar la cuenta
                    "INSERT INTO user (username, password, salt, email) VALUES (?,?,?,?)", (attempt['username'], attempt['password'], 
                            attempt['salt'], attempt['email'])
                )
                db.commit()

        return redirect(url_for('auth.login'))
    except Exception as e:
        print(e)
        return redirect(url_for('auth.login'))


@bp.route('/register', methods=("GET", "POST"))
def register():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == "POST":
            username = request.form["username"]
            username = username.replace("SELECT", "").replace("INSERT", "").replace(
                "DELETE", "").replace("UPDATE", "").replace("WHERE", "")
            password = request.form["password"]
            password = password.replace("SELECT", "").replace("INSERT", "").replace(
                "DELETE", "").replace("UPDATE", "").replace("WHERE", "")
            password1 = request.form["password1"]
            password1 = password1.replace("SELECT", "").replace("INSERT", "").replace(
                "DELETE", "").replace("UPDATE", "").replace("WHERE", "")
            email = request.form["email"]
            email = email.replace("SELECT", "").replace("INSERT", "").replace(
                "DELETE", "").replace("UPDATE", "").replace("WHERE", "")

            db = get_db()
            error = None

            if not username:
                error = 'Se requiere nombre de usuario.'
                flash(error)
                return render_template("auth/register.html")

            if not utils.isUsernameValid(username):
                error = "El nombre de usuario debe ser alfanumérico más '.','_','-'"
                flash(error)
                return render_template("auth/register.html")

            if not password:
                error = 'Se requiere contraseña.'
                flash(error)
                return render_template('auth/register.html')

            if not password1:
                error = 'Se requiere confirmación de contraseña.'
                flash(error)
                return render_template('auth/register.html')

            if password1 != password:
                error = 'Ambas contraseñas deben ser iguales.'
                flash(error)
                return render_template('auth/register.html')

            # Verifica que en la tabla usuarios no exista el usuario ingresado
            if db.execute("SELECT id FROM user WHERE username = ?", (username,)).fetchone() is not None:
                error = 'El usuario: {} ya está registrado.'.format(username)
                flash(error)
                return render_template("auth/register.html")

            if ((not email) or (not utils.isEmailValid(email))):
                error = 'Dirección de correo electrónico no válida.'
                flash(error)
                return render_template('auth/register.html')

            # Verifica que en la tabla email no exista el email ingresado
            if db.execute('SELECT id FROM user WHERE email = ?', (email,)).fetchone() is not None:
                error = 'El email {} ya está registrado.'.format(email)
                flash(error)
                return render_template("auth/register.html")

            if (not utils.isPasswordValid(password)):
                error = 'La contraseña debe ser de 8 caracteres y debe contener al menos una letra minúscula, una letra mayúscula y un número.'
                flash(error)
                return render_template('auth/register.html')

            salt = hex(random.getrandbits(128))[2:]
            hashP = generate_password_hash(password + salt)
            number = hex(random.getrandbits(512))[2:]

            db.execute( # Agrega los datos a la tabla de activationlink
                "INSERT INTO activationlink (challenge, state, username, password, salt, email) VALUES (?, ?, ?, ?, ?, ?)",
                (number, utils.U_UNCONFIRMED, username, hashP, salt, email)
            )
            db.commit()

            credentials = db.execute(
                'Select user,password from credentials where name=?', (
                    utils.EMAIL_APP,)
            ).fetchone()

            content = 'Hola, para activar su cuenta, haga clic en este enlace ' + \
                flask.url_for('auth.activate', _external=True) + \
                '?auth=' + number

            send_email(credentials, receiver=email,
                    subject='Activate your account', message=content)

            flash('Por favor revise su correo electrónico registrado para activar su cuenta.')
            return render_template('auth/login.html')

        return render_template("auth/register.html")
    except:
        return render_template('auth/register.html')


@bp.route('/confirm', methods=("GET", "POST"))
def confirm():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == "POST":
            password = request.form["password"]
            password = password.replace("SELECT", "").replace("INSERT", "").replace(
                "DELETE", "").replace("UPDATE", "").replace("WHERE", "")
            password1 = request.form["password1"]
            password1 = password1.replace("SELECT", "").replace("INSERT", "").replace(
                "DELETE", "").replace("UPDATE", "").replace("WHERE", "")
            authid = request.form['authid']
            authid = authid.replace("SELECT", "").replace("INSERT", "").replace(
                "DELETE", "").replace("UPDATE", "").replace("WHERE", "")

            if not authid:
                flash('Invalido')
                return render_template('auth/forgot.html')

            if not password:
                flash('Se requiere contraseña')
                return render_template('auth/change.html', number=authid)

            if not password1:
                flash('Se requiere confirmación de contraseña')
                return render_template("auth/change.html", number=authid)

            if password1 != password:
                flash('Ambos valores deben ser iguales.')
                return render_template("auth/change.html", number=authid)

            if not utils.isPasswordValid(password):
                error = 'La contraseña debe ser de 8 caracteres y debe contener al menos una letra minúscula, una letra mayúscula y un número.'
                flash(error)
                return render_template('auth/change.html', number=authid)

            db = get_db()
            attempt = db.execute( # Guarda en la variable attemp los datos de la tabla forgotlink que tengan el number (authid) del link y el state active 
                "SELECT * FROM forgotlink WHERE challenge = ? AND state = ?", (authid, utils.F_ACTIVE)
            ).fetchone()

            if attempt is not None:
                db.execute( # Actualiza el state de la tabla forgotlink 
                    "UPDATE forgotlink SET state = ? WHERE id = ?", (utils.F_INACTIVE, attempt['id'])
                )
                salt = hex(random.getrandbits(128))[2:]
                hashP = generate_password_hash(password + salt)
                db.execute( # Actualiza los datos de la tabla usuario
                    "UPDATE user SET password = ?, salt = ? WHERE id = ?", (hashP, salt, attempt['userid'])
                )
                db.commit()
                return redirect(url_for('auth.login'))
            else:
                flash('Invalido')
                return render_template('auth/forgot.html')

        return render_template("auth/forgot.html")
    except:
        return render_template('auth/forgot.html')


@bp.route('/change', methods=('GET', 'POST'))
def change():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == "GET":
            number = request.args['auth']

            db = get_db()
            attempt = db.execute( # Guarda en la variable attemp los datos de la tabla forgotlink que tengan el number del link y el state unconfirmed 
                "SELECT * FROM forgotlink WHERE challenge = ? AND state = ?", (number, utils.F_ACTIVE)
            ).fetchone()

            if attempt is not None:
                return render_template('auth/change.html', number=number)

        return render_template('auth/forgot.html')
    except:
        return render_template("auth/forgot.html")


@bp.route('/forgot', methods=('GET', 'POST'))
def forgot():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST':
            email = request.form["email"]
            email = email.replace("SELECT", "").replace("INSERT", "").replace(
                "DELETE", "").replace("UPDATE", "").replace("WHERE", "")

            if ((not email) or (not utils.isEmailValid(email))):
                error = 'Dirección de correo electrónico no válida'
                flash(error)
                return render_template('auth/forgot.html')

            db = get_db()
            user = db.execute( # Se verifica si el email ingresado existe en la base de datos
                "SELECT * FROM user WHERE email = ?", (email,)
            ).fetchone()

            if user is not None:
                number = hex(random.getrandbits(512))[2:]

                # Creo que esta linea es innecesaria
                # db.execute(  Se modifica la tabla forgotlink QUERY, (utils.F_INACTIVE, user['id']))

                db.execute( # Se agrega a la tabla forgotlink el id del usuario que va a cambiar de password, el change y el state
                    "INSERT INTO forgotlink (userid, challenge, state) VALUES (?,?,?)", 
                    (user['id'], number, utils.F_ACTIVE)
                )
                db.commit()

                credentials = db.execute(
                    'Select user,password from credentials where name=?', (
                        utils.EMAIL_APP,)
                ).fetchone()

                content = 'Hola, para cambiar su contraseña, por favor haga clic en este enlace ' + \
                    flask.url_for('auth.change', _external=True) + \
                    '?auth=' + number

                send_email(credentials, receiver=email,
                        subject='New Password', message=content)

                flash('Por favor verifique en su correo electrónico registrado.')
            else:
                error = 'El correo electrónico no está registrado'
                flash(error)

        return render_template('auth/forgot.html')
    except:
        return render_template("auth/forgot.html")


@bp.route('/login', methods=("GET", "POST"))
def login():
    try:
        if g.user: 
            return redirect(url_for('inbox.show'))

        if request.method == "POST":
            username = request.form["username"]
            username = username.replace("SELECT", "").replace("INSERT", "").replace(
                "DELETE", "").replace("UPDATE", "").replace("WHERE", "")
            password = request.form["password"]
            password = password.replace("SELECT", "").replace("INSERT", "").replace(
                "DELETE", "").replace("UPDATE", "").replace("WHERE", "")

            if not username:
                error = 'Nombre de usuario Campo obligatorio'
                flash(error)
                return render_template('auth/login.html')

            if not password:
                error = 'Contraseña Campo obligatorio'
                flash(error)
                return render_template("auth/login.html")

            db = get_db()
            error = None
            user = db.execute(
                'SELECT * FROM user WHERE username = ?', (username,)
            ).fetchone()

            if user is None:
                error = 'Nombre de usuario o contraseña incorrecta'
            elif not check_password_hash(user['password'], password + user['salt']):
                error = 'Nombre de usuario o contraseña incorrecta'

            if error is None:
                session.clear()
                session['user_id'] = user["id"]
                return redirect(url_for('inbox.show'))

            flash(error)

        return render_template("auth/login.html")
    except:
        return render_template('auth/login.html')


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")
    
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute( # Se piden los datos del id que inicio sesion en la tabla user. Si g.user tiene datos, significa que ya se inicio sesion
            "SELECT * FROM user WHERE id = ?", (user_id,)
        ).fetchone()


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view


def send_email(credentials, receiver, subject, message):
    # Create Email
    email = EmailMessage()
    email["From"] = credentials['user']
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)

    # Send Email
    smtp = smtplib.SMTP("smtp-mail.outlook.com", port=587)
    smtp.starttls()
    smtp.login(credentials['user'], credentials['password'])
    smtp.sendmail(credentials['user'], receiver, email.as_string())
    smtp.quit()
