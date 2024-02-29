from .base_command import BaseCommannd
from ..models.user import User, UserSchema, UserJsonSchema
from ..session import Session
from ..errors.errors import IncompleteParams, UserAlreadyExists
from sqlalchemy import or_

class CreateUser(BaseCommannd):
  def __init__(self, data):
    self.data = data
  
  def execute(self):
    try:
      posted_user = UserSchema(
        only=('nombre', 'apellido', 'email', 'phone', 'password')
      ).load(self.data)
      print(posted_user)
      user = User(**posted_user)
      session = Session()
      
      if self.email_exist(session, self.data['email']):
        session.close()
        raise UserAlreadyExists()

      session.add(user)
      session.commit()

      new_user = UserJsonSchema().dump(user)
      session.close()

      return new_user
    except TypeError:
      raise IncompleteParams()
  
  def email_exist(self, session, email):
    return len(session.query(User).filter_by(email=email).all()) > 0