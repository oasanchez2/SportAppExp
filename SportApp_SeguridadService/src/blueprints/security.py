from flask import Flask, jsonify, request, Blueprint
from ..commands.create_user import CreateUser
from ..commands.generate_token import GenerateToken
from ..commands.get_user import GetUser
from ..commands.reset import Reset
from ..commands.confirm_user import ConfirmUser
from ..commands.forgot_user import ForgotUser
from ..commands.confirm_forgot_user import ConfirmForgotUser

security_blueprint = Blueprint('users', __name__)

@security_blueprint.route('/users', methods = ['POST'])
def create():
    user = CreateUser(request.get_json()).execute()
    return jsonify(user), 201

@security_blueprint.route('/users/confirm', methods = ['POST'])
def confirm():
    result = ConfirmUser(request.get_json()).execute()
    return jsonify(result), 201

@security_blueprint.route('/users/forgot', methods = ['POST'])
def forgot():
    result = ForgotUser(request.get_json()).execute()
    return jsonify(result), 201

@security_blueprint.route('/users/confirm_forgot', methods = ['POST'])
def confirm_forgot():
    result = ConfirmForgotUser(request.get_json()).execute()
    return jsonify(result), 201

@security_blueprint.route('/users/auth', methods = ['POST'])
def auth():
    user = GenerateToken(request.get_json()).execute()
    return jsonify(user)

@security_blueprint.route('/users/me', methods = ['GET'])
def show():
    user = GetUser(auth_token()).execute()
    return jsonify(user)

@security_blueprint.route('/', methods = ['GET'])
def ping():
    return 'pong'

@security_blueprint.route('/users/reset', methods = ['POST'])
def reset():
    Reset().execute()
    return jsonify({'status': 'OK'})

def auth_token():
    if 'Authorization' in request.headers:
        authorization = request.headers['Authorization']
    else:
        authorization = None
    return authorization