import qrcode
import redis
from io import BytesIO
from flask import (
    Flask,
    request,
    send_file,
    redirect,
    url_for,
    jsonify,
    session,
    render_template,
)
from flask_session import Session

from functools import wraps

import hashlib
import time
import uuid

import re

import mysql.connector

import bcrypt

from datetime import timedelta

base_url = "s-boska-24.dev.spsejecna.net"

db_connection = mysql.connector.connect(
    host="localhost",
    user="test",
    password="test1",
    database="qrkod",
)

qr_redis = redis.StrictRedis(
    host="localhost",
    port=6379,
    db=0,
    decode_responses=True,
)

app = Flask(__name__)

app.config["SECRET_KEY"] = "A@das510cy5cc51waaqd51v15c15aas1874897ac"
app.config["SESSION_TYPE"] = "redis"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=10)
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_REDIS"] = redis.StrictRedis(host="localhost", port=6379)

Session(app)


@app.route("/check-username", methods=["POST"])
def check_username():
    username = request.form.get("username")

    cursor = db_connection.cursor()

    try:
        cursor.execute("SELECT * FROM user WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user:
            return jsonify({"exists": True}), 200
        return jsonify({"exists": False}), 200
    except Exception as e:
        return render_template(
            "error.jinja", message="Database error while checking username: " + str(e)
        )


@app.route("/", methods=["GET"])
def main_page():
    is_logged_in = "username" in session

    try:
        username = session["username"]
    except KeyError:
        username = None
        
        

    return render_template(
        "main.jinja",
        registration_page_url=url_for("register"),
        login_page_url=url_for("login_form"),
        logout=url_for("logout"),
        username=username,
        is_logged_in=is_logged_in,
    )


@app.route("/register", methods=["GET"])
def register():
    return render_template(
        "register.jinja",
        qr_code_page_url=url_for("register_qr"),
        check_username_url=url_for("check_username"),
    )


@app.route("/register_qr", methods=["POST"])
def register_qr():
    username = request.form.get("username")

    url_token = get_unique_url(username)

    qr_redis.setex(url_token, 300, username)

    qr_data = f"{base_url}/register/{url_token}"

    print(qr_data)

    qr = qrcode.QRCode(
        version=2,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )

    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image()
    img_io = BytesIO()
    img.save(img_io, "PNG")
    img_io.seek(0)

    return send_file(img_io, mimetype="image/png")


@app.route("/register/<token>")
def finish_registration(token):
    fetched_username = qr_redis.get(token)

    if fetched_username is None:
        return render_template(
            "error.jinja", message="The QR code you just scanned has sadly expired :("
        )

    return render_template(
        "qr_register.jinja",
        finalize_registration_url=url_for("finalize"),
        key=token,
        username=fetched_username,
    )


@app.route("/finalize-register", methods=["POST"])
def finalize():
    username = request.form.get("username")
    password = request.form.get("password")
    key = request.form.get("key")

    if not username or not password or not key:
        return render_template(
            "error.jinja",
            "Something is seriously messed up. Didn't get all required data when you sent a form",
        )

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    cursor = db_connection.cursor()

    try:
        cursor.execute(
            "INSERT INTO user (username, password) VALUES (%s, %s)",
            (username, hashed_password),
        )
        db_connection.commit()
    except Exception as e:
        return render_template(
            "error.jinja",
            message="Database error while finalizing registration: " + str(e),
        )

    qr_redis.delete(key)

    return redirect(url_for("main_page"))


@app.route("/login", methods=["GET"])
def login_form():
    return render_template("login.jinja", login_url=url_for("login"))


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    cursor = db_connection.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM user WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(
            password.encode("utf-8"), user["password"].encode("utf-8")
        ):
            session["username"] = user["username"]
            return redirect(url_for("main_page"))
        else:
            return render_template("error.jinja", message="Wrong password")
    except Exception as e:
        return render_template(
            "error.jinja", message="Database error while logging in: " + str(e)
        )


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("main_page"))


def get_unique_url(username):
    unique_id = str(uuid.uuid4())
    timestamp = str(time.time())
    combined = f"{unique_id}{timestamp}{username}"
    hashed = hashlib.sha256(combined.encode())
    url_token = hashed.hexdigest()
    return url_token


if __name__ == "__main__":
    app.run(debug=True)
