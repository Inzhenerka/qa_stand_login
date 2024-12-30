import os
from flask import Flask, request, redirect, url_for, render_template, jsonify
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_swagger import swagger
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URI']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

API_KEY = 'API_KEY123'  # FOR DEMO PURPOSES ONLY. DO NOT STORE API KEYS IN CODE!


def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if 'API_KEY' is in the query parameters
        # and if it matches the predefined API key
        if 'API_KEY' in request.args and request.args.get('API_KEY') == API_KEY:
            return f(*args, **kwargs)
        else:
            # If the API key is incorrect or not provided, return 401 Unauthorized
            return jsonify({"error": "API key is missing or incorrect"}), 401

    return decorated_function


class User(db.Model):
    __table_args__ = {'schema': 'qa_stand'}
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
    return redirect(url_for('login'))


@app.route('/user_details/<username>')
def user_details(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user_details.html', user=user)


# REST API to create a new user
@app.route('/api/users', methods=['POST'])
@require_api_key
def create_user():
    """
    Create a new user
    ---
    definitions:
      - schema:
          id: User
          required:
            - username
            - password
            - name
          properties:
            username:
              type: string
              description: Unique username
              example: testuser
            password:
              type: string
              description: Password of user
              example: password123
            name:
              type: string
              description: name for user in free form
              example: Автоматизатор Тестович
            jobtitle:
              type: string
              description: job title for user
              example: Тестировщик
            age:
              type: number
              description: Age of user
              example: 60
            description:
              type: string
              description: Description of user (comment)
              example: Лучший тестер в мире
            admin:
              type: boolean
              description: User has admin rights
              example: false
    parameters:
      - in: body
        name: body
        schema:
          $ref: "#/definitions/User"
    responses:
      201:
        description: User created
      400:
        description: User already exists
      401:
        description: Unauthorized
    security:
      - ApiKeyAuth: []
    """
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user:
        return jsonify({'message': 'User already exists.'}), 400
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(
        username=data['username'],
        password=hashed_password,
        name=data['name'],
        jobtitle=data.get('jobtitle'),
        age=data.get('age'),
        description=data.get('description'),
        admin=data.get('admin', False),
        readonly=False
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created.'}), 201


# REST API to get user details
@app.route('/api/users/<username>', methods=['GET'])
@require_api_key
def get_user(username):
    """
    Get user details
    ---
    parameters:
      - name: username
        in: path
        type: string
        required: true
        description: Username of the user
    responses:
      200:
        description: User details
        schema:
          $ref: "#/definitions/User"
      404:
        description: User not found
      401:
        description: Unauthorized
    security:
      - ApiKeyAuth: []
    """
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found.'}), 404
    return jsonify({
        'username': user.username,
        'name': user.name,
        'jobtitle': user.jobtitle,
        'age': user.age,
        'description': user.description,
        'admin': user.admin
    })


# REST API to update a user
@app.route('/api/users/<username>', methods=['PUT'])
@require_api_key
def update_user(username):
    """
    Update user details
    ---
    parameters:
      - name: username
        in: path
        type: string
        required: true
        description: Username of the user
      - in: body
        name: body
        schema:
          $ref: "#/definitions/User"
    responses:
      200:
        description: User updated
      403:
        description: Cannot modify readonly user
      404:
        description: User not found
      401:
        description: Unauthorized
    security:
      - ApiKeyAuth: []
    """
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found.'}), 404
    if user.readonly:
        return jsonify({'message': 'Cannot modify readonly user.'}), 403
    data = request.get_json()
    if 'password' in data:
        user.password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    if 'name' in data:
        user.name = data['name']
    if 'jobtitle' in data:
        user.jobtitle = data['jobtitle']
    if 'age' in data:
        user.age = data['age']
    if 'description' in data:
        user.description = data['description']
    if 'admin' in data:
        user.admin = data['admin']
    db.session.commit()
    return jsonify({'message': 'User updated.'})


# REST API to delete a user
@app.route('/api/users/<username>', methods=['DELETE'])
@require_api_key
def delete_user(username):
    """
    Delete user
    ---
    parameters:
      - name: username
        in: path
        type: string
        required: true
        description: Username of the user
    responses:
      200:
        description: User deleted
      403:
        description: Cannot delete readonly user
      404:
        description: User not found
      401:
        description: Unauthorized
    security:
      - ApiKeyAuth: []
    """
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found.'}), 404
    if user.readonly:
        return jsonify({'message': 'Cannot delete readonly user.'}), 403
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted.'})


@app.route('/api/spec')
def spec():
    swag = swagger(app)
    swag['info']['title'] = 'QA Stand API (inzhenerka.tech)'
    swag['info']['description'] = 'Описание API для управления пользователями.' +\
        '\n\nДля курса "Основы QA" от [inzhenerka.tech](https://inzhenerka.tech/)' +\
        '\n\n**API KEY: `API_KEY123`**'
    swag['securityDefinitions'] = {'ApiKeyAuth': {'type': 'apiKey', 'in': 'query', 'name': 'API_KEY'}}
    return jsonify(swag)


@app.route('/docs', methods=['GET'])
def docs():
    return render_template('docs.html')


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'OK'})

with app.app_context():
    db.create_all()
