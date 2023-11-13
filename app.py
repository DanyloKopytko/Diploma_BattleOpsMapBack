import os
import jwt
import base64

from flask_cors import CORS
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, jsonify, request


from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from sqlalchemy import func, and_
from functools import wraps


basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] =\
        'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'JWT_SECRET_KEY_FOR_DECODING'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(100), unique = True)
    password = db.Column(db.String(80))
    rank = db.Column(db.String(50))
    army_location = db.Column(db.String(100))

class PositionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    position_id = db.Column(db.Integer)
    name = db.Column(db.String(100))
    enemy = db.Column(db.Boolean, unique=False, default=False)
    position_type = db.Column(db.Integer)
    position_count = db.Column(db.Integer)
    description = db.Column(db.String(500))
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    updated_time = db.Column(db.DateTime, default=datetime.utcnow)
    is_landmark = db.Column(db.Boolean, unique=False, default=False)

    @property
    def serialize(self):
       """Return object data in easily serializable format"""
       return {
           'id': self.position_id,
           'enemy': self.enemy,
           'isLandmark': self.is_landmark,
           'type': self.position_type,
           'description'  : self.description,
           'count': self.position_count,
           'name': self.name,
           'lat': self.lat,
           'lng': self.lng
       }

class PositionType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))

class Position(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    enemy = db.Column(db.Boolean, unique=False, default=False)
    is_landmark = db.Column(db.Boolean, unique=False, default=False)
    position_type = db.Column(db.Integer)
    position_count = db.Column(db.Integer)
    description = db.Column(db.String(500))
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)

    @property
    def serialize(self):
       """Return object data in easily serializable format"""
       return {
           'id': self.id,
           'enemy': self.enemy,
           'type': self.position_type,
           'isLandmark': self.is_landmark,
           'description'  : self.description,
           'count': self.position_count,
           'name': self.name,
           'lat': self.lat,
           'lng': self.lng
       }

def decode_passphrase(passphrase: str):
    password=passphrase.encode()
    salt = b'q\xe3Q5\x8c\x19~\x17\xcb\x88\xc6A\xb8j\xb4\x85'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query\
                .filter_by(username = data['username'])\
                .first()
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users context to the routes
        return  f(current_user, *args, **kwargs)
    return decorated

@app.route('/login', methods =['POST'])
def login():
    # creates dictionary of form data
    file = request.files['file'].read()
    passphrase=request.form['passphrase']
    try:
        fernet = Fernet(decode_passphrase(passphrase))
        decrypted = fernet.decrypt(file)
        username, password = decrypted.decode("utf-8").split(" ")
    except Exception:
        return jsonify({
                'message' : 'Bad is passphrase !!'
            }), 401

    user = User.query\
        .filter_by(username = username)\
        .first()
    
    if not user:
        # returns 401 if user does not exist
        return "User does not exist", 401

  
    if user.password == password:
        # generates the JWT Token
        token = jwt.encode({
            'username': user.username,
            'exp' : datetime.utcnow() + timedelta(minutes = 24*60)
        }, app.config['SECRET_KEY'])
  
        return jsonify({'token' : token})
    # returns 403 if password is wrong
    return "Wrong Password !!", 403


@app.route('/positions', methods=['GET'])
@token_required
def get_positions(user):
    data = Position.query.all()
    result = [d.serialize for d in data]
    return jsonify(result)


@app.route('/chronology', methods=['GET'])
@token_required
def history_positions(user):
    selected_date = datetime.strptime(request.args.get('date'), "%Y-%m-%d").date()
    subq = db.session.query(
        PositionHistory.position_id,
        func.max(PositionHistory.updated_time).label('maxdate')
    ).filter(func.date(PositionHistory.updated_time)<=selected_date) \
     .group_by(PositionHistory.position_id).subquery('t2')

    data = db.session.query(PositionHistory).join(
        subq,
        and_(
            PositionHistory.position_id == subq.c.position_id,
            PositionHistory.updated_time == subq.c.maxdate
        )
    ).all()
    result = [d.serialize for d in data]
    return jsonify(result)


@app.route('/position', methods=['POST'])
@token_required
def add_position(user):
    data = request.get_json()
    position = Position(
        name=data["name"],
        position_type=data["type"],
        enemy=data["enemy"],
        position_count=data["count"],
        description=data["description"],
        lat=data['lat'],
        lng=data['lng'],
        is_landmark=data.get('isLandmark', False)
    )
    db.session.add(position)
    db.session.commit()
    result = position.serialize
    position_history = PositionHistory(
        position_id=result["id"],
        name=result["name"],
        position_type=result["type"],
        enemy=result["enemy"],
        position_count=result["count"],
        description=result["description"],
        lat=result['lat'],
        lng=result['lng'],
        is_landmark=result['isLandmark']
    )
    db.session.add(position_history)
    db.session.commit()
    return jsonify(result)


@app.route('/position', methods=['PUT'])
@token_required
def edit_position(user):
    data = request.get_json()
    position = Position.query.get(data["id"])
    position.name = data["name"]
    position.position_type=data["type"]
    position.enemy=data["enemy"]
    position.position_count=data["count"]
    position.description=data["description"]
    position.lat=data['lat']
    position.lng=data['lng']

    position_history = PositionHistory(
        position_id=data["id"],
        name=data["name"],
        position_type=data["type"],
        enemy=data["enemy"],
        position_count=data["count"],
        description=data["description"],
        lat=data['lat'],
        lng=data['lng'],
        is_landmark=position.is_landmark
    )
    db.session.add(position_history)
    db.session.commit()
    return jsonify(position.serialize)


@app.route('/position', methods=['PATCH'])
@token_required
def modify_position(user):
    data = request.get_json()
    position = Position.query.get(data["id"])
    position.lat = data["lat"]
    position.lng = data["lng"]

    position_history = PositionHistory(
        position_id=position.id,
        name=position.name,
        position_type=position.position_type,
        enemy=position.enemy,
        position_count=position.position_count,
        description=position.description,
        lat=position.lat,
        lng=position.lng,
        is_landmark=position.is_landmark
    )
    db.session.add(position_history)
    db.session.commit()
    return jsonify(position.serialize)


@app.route('/position', methods=['DELETE'])
@token_required
def delete_position(user):
    data = request.get_json()
    position = Position.query.get(data["id"])

    position_history = PositionHistory(
        position_id=position.id,
        name=position.name,
        position_type=position.position_type,
        enemy=position.enemy,
        position_count=position.position_count,
        description=position.description,
        lat=0,
        lng=0,
        is_landmark=position.is_landmark
    )
    db.session.add(position_history)

    db.session.delete(position)
    db.session.commit()
    return jsonify(success=True)

