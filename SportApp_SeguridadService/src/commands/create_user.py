from .base_command import BaseCommannd
from ..models.user import User, UserSchema, UserJsonSchema
from ..session import Session
from ..errors.errors import IncompleteParams, UserAlreadyExists, ClientExError, InvalidPasswordError,InvalidEamilError, ClientInvalidParameterError
import boto3
import hmac
import hashlib
import base64
import os
import re

class CreateUser(BaseCommannd):
  def __init__(self, data):
    self.data = data
  
  def execute(self):
    try:
      posted_user = UserSchema(
        only=('nombre', 'apellido', 'email', 'phone', 'password')
      ).load(self.data)
      print(posted_user)
      
      if not self.verificar_datos(posted_user["email"]):
         raise InvalidEamilError
      """
      user = User(**posted_user)
      session = Session()
      
      if self.email_exist(session, self.data['email']):
        session.close()
        raise UserAlreadyExists()

      session.add(user)
      session.commit()

      new_user = UserJsonSchema().dump(user)
      session.close()
      print("estoy aqui")
      """
      
      # Configurar cliente de Cognito
      client = boto3.client('cognito-idp', region_name='us-east-1')

      try:        
        # Crear usuario en Cognito
        response = client.sign_up(
            ClientId= os.environ['APP_SPORTAPP'],
            Username= posted_user["email"] ,
            Password= posted_user["password"],
            SecretHash= self.calculate_secret_hash(os.environ['APP_SPORTAPP'], os.environ['APP_SPORTAPPCLIENT'], posted_user["email"]),
            UserAttributes = [{"Name": "phone_number", "Value": posted_user["phone"]},
                              {"Name": "given_name", "Value": posted_user["nombre"]},
                              {"Name": "family_name", "Value": posted_user["apellido"]}]
        )
             
        new_user = UserJsonSchema().dump(posted_user)  
        return new_user 
      except client.exceptions.UsernameExistsException:
          raise UserAlreadyExists
      except client.exceptions.InvalidPasswordException:
          raise InvalidPasswordError
      except client.exceptions.InvalidParameterException:
          raise ClientInvalidParameterError
      except client.exceptions.ClientError as e:
          print(str(e))
          raise ClientExError
      
    except TypeError as te:
      print("Error en el primer try:", str(te))
      raise IncompleteParams()
  
  def email_exist(self, session, email):
    return len(session.query(User).filter_by(email=email).all()) > 0
  
  def calculate_secret_hash(self,client_id, client_secret, username):
    msg = username + client_id
    dig = hmac.new(str(client_secret).encode('utf-8'), 
                   msg=str(msg).encode('utf-8'), 
                   digestmod=hashlib.sha256).digest()
    return base64.b64encode(dig).decode()
  
  def verificar_datos(self,email):
    # Expresión regular para validar el formato de correo electrónico
    # patron = r'^[\w\.-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'
    patron = r'^[(a-z0-9\_\-\.)]+@[(a-z0-9\_\-\.)]+\.[(a-z)]{2,4}$'
    # Utilizar el método match() de la clase re para verificar si el correo cumple con el patrón
    if re.match(patron, email.lower()):
        return True
    else:
        return False