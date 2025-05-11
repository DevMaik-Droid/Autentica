from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
#obtener conexion a la base de datos
import os
import psycopg2
from urllib.parse import urlparse

import sqlite3

app = Flask(__name__)
app.secret_key = "clavesecreta"

#Configurar flask-login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


# Reemplaza tu función get_db_connection por:
def get_db_connection():
    if 'DATABASE_URL' in os.environ:  # Para producción
        result = urlparse(os.environ['DATABASE_URL'])
        conn = psycopg2.connect(
            dbname=result.path[1:],
            user=result.username,
            password=result.password,
            host=result.hostname,
            port=result.port
        )
    else:  # Para desarrollo local
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
    return conn

#Clase Usuario
class User(UserMixin):
    def __init__(self, id, username, password, name=None,email=None):
        self.id = id
        self.username = username
        self.password = password
        self.name = name
        self.email = email

    @staticmethod
    def get_by_id(user_id):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?',(user_id,)).fetchone()
        conn.close()

        if user:
            return User(user['id'],user['username'],user['password'],user['name'],user['email'])
        return None
    
    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?',(username, )).fetchone()
        conn.close()
        if user:
            return User(user['id'],user['username'],user['password'],user['name'],user['email'])
        return None
    
@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        password = name = request.form['password']
        hash_pass = generate_password_hash(password)

        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO users (name, email, username, password) VALUES (?,?,?,?)',
                (name, email, username, hash_pass)
            )
            conn.commit()
            flash("Usuario registrado correctamente, inicia session", 'success')
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("El nombre de usuario ya existe")
        finally:
            conn.close()
    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.get_by_username(username)
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('inicio de session exitoso', 'success')
            return redirect(url_for("dashboard"))
        else:
            flash("Credenciales invalidades", "danger")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", username=current_user.username,name=current_user.name)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("has cerrado session", "info")
    return redirect(url_for("login"))

if __name__ == '__main__':

    app.run(debug=True)
