from .base_command import BaseCommannd
from ..models.user import User, UserJsonSchema
from ..models.log_sesion import LogSesion
from ..session import Session
from ..errors.errors import Unauthorized, IncompleteParams, UserNotFoundError, UserNotConfirmedError, ClientExError, ExpiredCodeExceptionError
import bcrypt
import boto3
import hmac
import hashlib
import base64
import os
from botocore.exceptions import ClientError

class ResponseMfaChallenge(BaseCommannd):
  def __init__(self, data):
    if 'user_name' not in data or 'session' not in data or 'mfa_code' not in data:
      raise IncompleteParams()

   # Configurar cliente de Cognito
    self.client = boto3.client('cognito-idp', region_name='us-east-1')
    self.user_name = data['user_name']
    self.session = data['session']
    self.mfa_code = data['mfa_code']
 
  def execute(self):     
        try:
            credentials = boto3.Session().get_credentials()
            print("Credenciales boto - Access Key:", credentials.access_key)
            print("Credenciales boto - Secret Key:", credentials.secret_key)

            response = self.client.admin_respond_to_auth_challenge(
                UserPoolId=os.environ['APP_SPORTAAIDGRUPO'],
                ClientId=os.environ['APP_SPORTAPP'],
                ChallengeName="SOFTWARE_TOKEN_MFA",
                Session=self.session,
                ChallengeResponses={
                    'USERNAME': self.user_name,
                    'SOFTWARE_TOKEN_MFA_CODE': self.mfa_code,
                    'SECRET_HASH': self.calculate_secret_hash(os.environ['APP_SPORTAPP'], os.environ['APP_SPORTAPPCLIENT'], self.user_name)
                }                
            )
        except ClientError as err: 
            print(f"error.verify mfa: {err.response['Error']['Code']}: {err.response['Error']['Message']}")        
            if err.response['Error']['Code'] == 'NotAuthorizedException':
                raise Unauthorized
            elif err.response['Error']['Code'] == 'UserNotFoundException':
                raise UserNotFoundError
            elif err.response['Error']['Code'] == 'UserNotConfirmedException':
                raise UserNotConfirmedError
            elif err.response['Error']['Code'] == 'InvalidParameterException':
                raise IncompleteParams
            elif err.response['Error']['Code'] == 'ExpiredCodeException':
                raise ExpiredCodeExceptionError
            else:
                raise ClientExError   
        else:
            response.pop("ResponseMetadata", None)
            return response
        
  def calculate_secret_hash(self,client_id, client_secret, username):
    msg = username + client_id
    dig = hmac.new(str(client_secret).encode('utf-8'), 
                msg=str(msg).encode('utf-8'), 
                digestmod=hashlib.sha256).digest()
    return base64.b64encode(dig).decode()        