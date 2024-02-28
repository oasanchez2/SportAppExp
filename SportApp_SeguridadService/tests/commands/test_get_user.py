from src.commands.get_user import GetUser
from src.commands.create_user import CreateUser
from src.session import Session, engine
from src.models.model import Base
from src.models.user import User
from src.errors.errors import IncompleteParams
from src.errors.errors import Unauthorized
from datetime import datetime, timedelta

class TestGetUser():
  def setup_method(self):
    Base.metadata.create_all(engine)
    self.session = Session()
    
    self.data = {
      'username': 'william',
      'email': 'william@gmail.com',
      'password': '123456',
      'role':'candidato'
    }
    self.user = CreateUser(self.data).execute()

  def test_get_user_with_valid_token(self):
    token = self.user['token']
    user = GetUser(f'Bearer {token}').execute()

    assert user['id'] == self.user['id']
    assert user['token'] == self.user['token']
    assert user['expireAt'] == self.user['expireAt']


  def test_get_user_with_expired_token(self):
    queried_user = self.session.query(User).filter_by(id=self.user['id']).one()
    queried_user.expireAt = datetime.now() - timedelta(hours=1)
    self.session.commit()

    try:
      GetUser(f'Bearer {queried_user.token}').execute()
      assert False
    except Unauthorized:
      assert True


  def test_get_user_without_token(self):
    try:
      GetUser().execute()

      assert False
    except IncompleteParams:
      queried_user = self.session.query(User).filter_by(id=self.user['id']).one()
      assert self.user['token'] == queried_user.token
      assert True
  
  def teardown_method(self):
    self.session.close()
    Base.metadata.drop_all(bind=engine)