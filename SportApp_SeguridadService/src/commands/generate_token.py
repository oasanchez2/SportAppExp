from .base_command import BaseCommannd
from ..models.user import User, UserJsonSchema
from ..models.log_sesion import LogSesion
from ..session import Session
from ..errors.errors import Unauthorized, IncompleteParams, UserNotFoundError, UserNotConfirmedError, ClientExError, PasswordResetRequiredError
import bcrypt
import boto3
import hmac
import hashlib
import base64
import os
from botocore.exceptions import ClientError

class GenerateToken(BaseCommannd):
  def __init__(self, data, ip, user_agent):
    if 'username' not in data or 'password' not in data:
      raise IncompleteParams()

    self.username = data['username']
    self.password = data['password']
    self.ip = ip
    self.user_agent = user_agent
  
  def execute(self):
    session = Session()

    # Configurar cliente de Cognito
    client = boto3.client('cognito-idp', region_name='us-east-1')

    # Definir para iniciar sesión de un usuario
    try:
        response = client.initiate_auth(
            ClientId=os.environ['APP_SPORTAPP'],
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': self.username,
                'PASSWORD': self.password,
                'SECRET_HASH': self.calculate_secret_hash(os.environ['APP_SPORTAPP'], os.environ['APP_SPORTAPPCLIENT'], self.username)
            }
        )
        print(response)
        self.log_sesiones(session,self.username,self.ip,self.user_agent,'Ok')
        self.reglas_bloqueo(session, self.username)
        session.close()
        return response
        # Si necesitas el token de acceso, puedes obtenerlo de la respuesta:
        # access_token = response['AuthenticationResult']['AccessToken']
        # return access_token
    except ClientError as err: 
       print(f"Here's why: {err.response['Error']['Code']}: {err.response['Error']['Message']}")
       self.log_sesiones(session,self.username,self.ip,self.user_agent,err.response['Error']['Code'])
       self.reglas_bloqueo(session, self.username)
       session.close()
       if err.response['Error']['Code'] == 'NotAuthorizedException':
           raise Unauthorized
       elif err.response['Error']['Code'] == 'UserNotFoundException':
          raise UserNotFoundError
       elif err.response['Error']['Code'] == 'UserNotConfirmedException':
          raise UserNotConfirmedError
       elif err.response['Error']['Code'] == 'InvalidParameterException':
          raise IncompleteParams
       elif err.response['Error']['Code'] == 'PasswordResetRequiredException':
          raise PasswordResetRequiredError
       else:
          raise ClientExError
    
  def valid_password(self, salt, password, other_password):
    incoming_password = bcrypt.hashpw(
      other_password.encode('utf-8'), salt.encode('utf-8')
    ).decode()
    return incoming_password == password
  
  def calculate_secret_hash(self,client_id, client_secret, username):
    msg = username + client_id
    dig = hmac.new(str(client_secret).encode('utf-8'), 
                   msg=str(msg).encode('utf-8'), 
                   digestmod=hashlib.sha256).digest()
    return base64.b64encode(dig).decode()
  
  def log_sesiones(self,session, email, ip_origen, user_agent,codigo_sesion):
     try:
        log =  LogSesion(email,ip_origen,user_agent,codigo_sesion)
        session.add(log)
        session.commit()
        session.close()
     except TypeError as te:
        print("Error guardar log sesion:", str(te))
  
  def reglas_bloqueo(self,session, email):
     try:
        resultados = session.query(LogSesion).\
        filter_by(email=email, codigo_sesion='NotAuthorizedException').\
        order_by(LogSesion.createdAt.desc()).\
        limit(3).\
        all()
      
        # Filtra los resultados para contar la cantidad de filas con "NotAuthorizedException"
        count_not_authorized = sum(1 for resultado in resultados if resultado.codigo_sesion == 'NotAuthorizedException')

        if len(resultados) == count_not_authorized:
            pass
        
     except TypeError as te:
        print("Error validar regla bloqueo:", str(te))
     
     
      