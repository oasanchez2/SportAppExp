from .base_command import BaseCommannd
from ..models.user import User, UserJsonSchema
from ..session import Session
from ..errors.errors import ExeptionExError, IncompleteParams, CodeNotExistsError,CodeExpiredError
from datetime import datetime
import boto3
import hmac
import hashlib
import base64
import os
from botocore.exceptions import ClientError

class ConfirmUser(BaseCommannd):
  def __init__(self, data):
    if 'username' not in data or 'confirmation_code' not in data:
      raise IncompleteParams()
    
    self.username = data['username']
    self.confirmation_code = data['confirmation_code']
      
  def execute(self):
    session = Session()
    
    try:
        # Configurar cliente de Cognito
        client = boto3.client('cognito-idp', region_name='us-east-1')
        mnensaje = "ok"
        # Crear usuario en Cognito
        response = client.confirm_sign_up(
            ClientId= os.environ['APP_SPORTAPP'],
            Username= self.username,
            ConfirmationCode = self.confirmation_code,            
            SecretHash= self.calculate_secret_hash(os.environ['APP_SPORTAPP'], os.environ['APP_SPORTAPPCLIENT'], self.username)
          )
        return mnensaje
    except ClientError as err:       
        print(f"Couldn't confirm sign up for {self.username}. Here's why: {err.response['Error']['Code']}: {err.response['Error']['Message']}")
        if err.response['Error']['Code'] == 'CodeMismatchException':
           raise CodeNotExistsError
        elif err.response['Error']['Code'] == 'ExpiredCodeException':
            raise CodeExpiredError
        else:
           raise ExeptionExError        
  
  def calculate_secret_hash(self,client_id, client_secret, username):
    msg = username + client_id
    dig = hmac.new(str(client_secret).encode('utf-8'), 
                   msg=str(msg).encode('utf-8'), 
                   digestmod=hashlib.sha256).digest()
    return base64.b64encode(dig).decode()