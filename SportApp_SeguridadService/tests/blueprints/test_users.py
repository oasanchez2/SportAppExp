from src.session import Session, engine
from src.models.model import Base
from src.models.user import User
from application import application
from src.commands.create_user import CreateUser
import json
from datetime import datetime, timedelta

class TestUsers():
  def setup_method(self):
    Base.metadata.create_all(engine)
    self.session = Session()

  def test_create_user(self):
    with application.test_client() as test_client:
      response = test_client.post(
        '/users', json={
          'username': 'William',
          'password': '123456',
          'email': 'william@gmail.com',
          'role':'candidato'
        }
      )
      response_json = json.loads(response.data)

      assert response.status_code == 201
      assert 'id' in response_json
      assert 'createdAt' in response_json

  def test_create_user_already_exists(self):
    data = {
      'username': 'William',
      'password': '123456',
      'email': 'william@gmail.com',
      'role':'candidato'
    }
    CreateUser(data).execute()

    with application.test_client() as test_client:
      response = test_client.post(
        '/users', json=data
      )

      assert response.status_code == 412

  def test_create_missing_fields(self):
    data = {
      'username': 'William',
    }

    with application.test_client() as test_client:
      response = test_client.post(
        '/users', json=data
      )

      assert response.status_code == 400

  def test_generate_token(self):
    data = {
      'username': 'William',
      'password': '123456',
      'email': 'william@gmail.com',
      'role':'candidato'
    }
    CreateUser(data).execute()

    with application.test_client() as test_client:
      response = test_client.post(
        '/users/auth', json={
          'username': data['username'],
          'password': data['password']
        }
      )

      response_json = json.loads(response.data)

      assert response.status_code == 200
      assert 'id' in response_json
      assert 'token' in response_json
      assert 'expireAt' in response_json


  def test_generate_token_missing_fields(self):
    data = {
      'username': 'William',
      'password': '123456',
      'email': 'william@gmail.com',
      'role':'candidato'
    }
    CreateUser(data).execute()

    with application.test_client() as test_client:
      response = test_client.post(
        '/users/auth', json={
          'username': data['username']
        }
      )

      assert response.status_code == 400

  def test_generate_token_user_doesnt_exist(self):
    data = {
      'username': 'William',
      'password': '123456',
      'email': 'william@gmail.com'
    }

    with application.test_client() as test_client:
      response = test_client.post(
        '/users/auth', json={
          'username': data['username'],
          'password': data['password']
        }
      )

      assert response.status_code == 404

  def test_get_user(self):
    data = {
      'username': 'William',
      'password': '123456',
      'email': 'william@gmail.com',
      'role':'candidato'
    }
    user = CreateUser(data).execute()

    with application.test_client() as test_client:
      response = test_client.get(
        '/users/me', headers={
          'Authorization': f'Bearer {user["token"]}',
        }
      )
      response_json = json.loads(response.data)

      assert response.status_code == 200
      assert 'id' in response_json
      assert 'username' in response_json
      assert 'email' in response_json

  def test_get_user_invalid_token(self):
    with application.test_client() as test_client:
      response = test_client.get(
        '/users/me', headers={
          'Authorization': f'Bearer Invalid',
        }
      )

      assert response.status_code == 401

  def test_get_user_expired_token(self):
    data = {
      'username': 'William',
      'password': '123456',
      'email': 'william@gmail.com',
      'role':'candidato'
    }
    user = CreateUser(data).execute()

    queried_user = self.session.query(User).filter_by(id=user['id']).one()
    queried_user.expireAt = datetime.now() - timedelta(hours=1)
    self.session.commit()

    with application.test_client() as test_client:
      response = test_client.get(
        '/users/me', headers={
          'Authorization': f'Bearer {user["token"]}',
        }
      )

      assert response.status_code == 401

  def test_get_user_missing_token(self):
    with application.test_client() as test_client:
      response = test_client.get(
        '/users/me'
      )

      assert response.status_code == 400

  def test_ping(self):
    with application.test_client() as test_client:
      response = test_client.get(
        '/'
      )

      assert response.status_code == 200
      assert response.data.decode("utf-8") == 'pong'

  def test_reset(self):
    with application.test_client() as test_client:
      response = test_client.post(
        '/users/reset'
      )
      assert response.status_code == 200

  def teardown_method(self):
    self.session.close()
    Base.metadata.drop_all(bind=engine)