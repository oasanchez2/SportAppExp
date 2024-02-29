from marshmallow import  Schema, fields
from sqlalchemy import Column, String, DateTime, Double
from .model import Model, Base
import bcrypt
from datetime import datetime, timedelta
from uuid import uuid4

class User(Model, Base):
  __tablename__ = 'users'

  nombre = Column(String)
  apellido = Column(String)
  username = Column(String)
  email = Column(String)
  phone = Column(String)
  password = Column(String)
  salt = Column(String)
  token = Column(String)
  expireAt = Column(DateTime)

  def __init__(self, nombre, apellido, email, phone, password):
    Model.__init__(self)
    self.nombre = nombre
    self.apellido = apellido
    self.email = email
    self.phone =  phone
    password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    self.password = bcrypt.hashpw(password, salt).decode()
    self.salt = salt.decode()
    self.set_token()

  def set_token(self):
    self.token = uuid4()
    self.expireAt = datetime.now() + timedelta(hours=1)

class UserSchema(Schema):
  id = fields.Number()
  nombre = fields.Str()
  apellido = fields.Str()
  email = fields.Str()
  phone = fields.Str()  
  password = fields.Str()
  salt = fields.Str()
  token = fields.Str()
  expireAt = fields.DateTime()
  createdAt = fields.DateTime()
 

class UserJsonSchema(Schema):
  id = fields.Number()
  nombre = fields.Str()
  apellido = fields.Str()
  email = fields.Str()
  phone = fields.Str() 
  token = fields.Str()
  expireAt = fields.DateTime()
  createdAt = fields.DateTime()
  
  
