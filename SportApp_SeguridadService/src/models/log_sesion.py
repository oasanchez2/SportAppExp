from marshmallow import  Schema, fields
from sqlalchemy import Column, String, DateTime, Double
from .model import Model, Base


class LogSesion(Model, Base):
  __tablename__ = 'log_sesion'
  
  email = Column(String)
  ip_origen = Column(String)
  user_agent = Column(String)
  codigo_sesion = Column(String)
  

  def __init__(self, email, ip_origen, user_agent,codigo_sesion):
    Model.__init__(self)  
    self.email = email
    self.ip_origen =  ip_origen
    self.user_agent =  user_agent
    self.user_agent =  codigo_sesion
    
class LogSesionSchema(Schema):
  id = fields.Number()
  email = fields.Str()
  ip_origen = fields.Str()  
  user_agent = fields.Str()
  codigo_sesion = fields.Str()
  expireAt = fields.DateTime()
  createdAt = fields.DateTime()
 

class LogSesionJsonSchema(Schema):
  id = fields.Number()
  email = fields.Str()
  ip_origen = fields.Str() 
  user_agent = fields.Str()
  codigo_sesion = fields.Str()
  expireAt = fields.DateTime()
  createdAt = fields.DateTime()