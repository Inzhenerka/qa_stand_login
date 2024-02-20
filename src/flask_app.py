from flask import Flask, request, redirect, url_for, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from src.aws.secrets_manager import SecretsManager

sm = SecretsManager()
creds: dict = sm.get_secret_value('qa_stand/postgres/postgres')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = \
    f"postgresql+psycopg://{creds['username']}:{creds['password']}@{creds['host']}/{creds['dbname']}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(160), nullable=True)
    jobtitle = db.Column(db.String(80), nullable=True)
    age = db.Column(db.Numeric(), nullable=True)
    description = db.Column(db.String(500), nullable=True)
    admin = db.Column(db.Boolean(), nullable=True)
    readonly = db.Column(db.Boolean(), nullable=False)


# Login page route
@app.route('/', methods=['GET'])
def root():
    return redirect(url_for('login'))


# Login page route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        # !!!! BUG !!!!
        # Bug that allow to log in as admin without user and password
        # Perhaps it was introduced to simplify development but developer forgot to remove it
        if not username and not password:
            return redirect(url_for('user_details', username='admin'))
        # !!!! END OF BUG !!!!
        elif user and check_password_hash(user.password, password):
            # Redirect to user details page if authentication succeeds
            return redirect(url_for('user_details', username=username))
        else:
            return render_template('login_failed.html')
    return render_template('login.html')  # Your login page HTML file


@app.route('/logout')
def logout():
    # Here you can add any required logic to clear the session or cookies
    # For example: session.pop('user_id', None)
    return redirect(url_for('login'))


# User details page route
@app.route('/user/<username>')
def user_details(username):
    user = User.query.filter_by(username=username).first_or_404()
    # Assuming 'user_details.html' is a template that displays user information
    return render_template('user_details.html', user=user)


# REST API to create a new user
@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], password=hashed_password, role=data.get('role', 'user'))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created.'}), 201


# REST API to get user details
@app.route('/api/users/<username>', methods=['GET'])
def get_user(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found.'}), 404
    return jsonify({'username': user.username, 'role': user.role})


# REST API to update a user
@app.route('/api/users/<username>', methods=['PUT'])
def update_user(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found.'}), 404
    if user.role == 'admin':
        return jsonify({'message': 'Cannot modify admin user.'}), 403
    data = request.get_json()
    user.password = generate_password_hash(
        data['password'], method='pbkdf2:sha256'
    ) if 'password' in data else user.password
    db.session.commit()
    return jsonify({'message': 'User updated.'})


# REST API to delete a user
@app.route('/api/users/<username>', methods=['DELETE'])
def delete_user(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found.'}), 404
    if user.role == 'admin':
        return jsonify({'message': 'Cannot delete admin user.'}), 403
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted.'})
