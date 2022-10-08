from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, current_app, send_file
)

from app.auth import login_required
from app.db import get_db

bp = Blueprint('inbox', __name__, url_prefix='/inbox')


@bp.route("/getDB")
@login_required
def getDB():
    return send_file(current_app.config['DATABASE'], as_attachment=True)


@bp.route('/show')
@login_required
def show():
    db = get_db()

    user_id = g.user["id"]
    messages = db.execute( # Guarda en la variable messages los datos de la tabla message del id (user_id)
        "SELECT * FROM message WHERE to_id = ?", (user_id,)
    ).fetchall()

    return render_template("inbox/show.html", messages=messages)


@bp.route('/send', methods=('GET', 'POST'))
@login_required
def send():
    if request.method == 'POST':
        to_username = request.form["to"]
        to_username = to_username.replace("SELECT", "").replace("INSERT", "").replace(
            "DELETE", "").replace("UPDATE", "").replace("WHERE", "")
        subject = request.form["subject"]
        subject = subject.replace("SELECT", "").replace("INSERT", "").replace(
            "DELETE", "").replace("UPDATE", "").replace("WHERE", "")
        body = request.form["body"]
        body = body.replace("SELECT", "").replace("INSERT", "").replace(
            "DELETE", "").replace("UPDATE", "").replace("WHERE", "")

        db = get_db()

        if not to_username:
            flash('To field is required')
            return render_template("inbox/send.html")

        if not subject:
            flash('Subject field is required')
            return render_template('inbox/send.html')

        if not body:
            flash('Body field is required')
            return render_template("inbox/send.html")

        error = None
        userto = None

        userto = db.execute( # Se verifica si el usuario que recibirá el mensaje existe
            "SELECT * FROM user WHERE username = ?", (to_username,)
        ).fetchone()

        if userto is None:
            error = 'Recipient does not exist'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute( # Se agrega el username del usuario que envio el mensaje, el id del usuario que recibirá el mensaje, el subject y el body
                "INSERT INTO message (from_username, to_id, subject, body) VALUES (?,?,?,?)",
                (g.user["username"], userto['id'], subject, body)
            )
            db.commit()

            return redirect(url_for('inbox.show'))

    return render_template('inbox/send.html')
