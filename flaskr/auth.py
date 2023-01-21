import functools
import datetime
from flask import (
    Blueprint, abort, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db


bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/')
def index():
    db = get_db()
    user = db.execute(
        'SELECT id, username, email, branch, password, joined'
        ' FROM user'
    ).fetchall()
    return render_template('auth/register.html', user=user)

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        branch = request.form['branch']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not email:
            error = 'Email is required.'
        elif not branch:
            error = 'Branch is required.'
        elif not password:
            error = 'Password is required.'
        
        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, email, branch,  password) VALUES (?, ?, ?, ?)",
                    (username, email, branch, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registerd."
            else:
                return redirect(url_for("auth.login"))

        flash(error)
    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

#update user detail
def get_user(username, check_user=True):
    user = get_db().execute(
        'SELECT id, username, email, branch'
        ' FROM user'
        ' WHERE username = ?',
        (username,)
    ).fetchone()

    if user is None:
        abort(404, f"user {username} doesn't exist.")

    if check_user and user['username'] != g.user['username']:
        abort(403)

    return user

@bp.route('/update/<int:id>', methods=('GET', 'POST'))
@login_required
def update(id):
    user = get_user(id)
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        branch = request.form['branch']
        error = None

        if not username:
            error = 'Username is required.'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE user SET username = ?, email = ?, branch = ?'
                ' WHERE id = ?',
                (username, email, branch, id)
            )
            db.session.commit()
            flash("Updated <3")
            return redirect(url_for('auth/update'))

    return render_template('blog.index.html', user=user)

#upload file 

@bp.route('/profile', methods=('GET', 'POST'))
@login_required
def profile():
    return render_template('profile.html')
    