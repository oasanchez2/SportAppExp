from .base_command import BaseCommannd
from ..models.user import User, UserJsonSchema
from ..models.log_sesion import LogSesion
from ..session import Session
from ..errors.errors import Unauthorized, IncompleteParams, UserNotFoundError, UserNotConfirmedError, ClientExError, PasswordResetRequiredError, ClientInvalidParameterError
import bcrypt
import boto3
import hmac
import hashlib
import base64
import os
from botocore.exceptions import ClientError

class VerifyMfa(BaseCommannd):
  def __init__(self, data):
    if 'session' not in data or 'user_code' not in data:
      raise IncompleteParams()

   # Configurar cliente de Cognito
    self.client = boto3.client('cognito-idp', region_name='us-east-1')
    self.session = data['session']
    self.user_code = data['user_code']
 
  def execute(self):     
        try:
            response = self.client.verify_software_token(
                Session=self.session, UserCode=self.user_code
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
            elif err.response['Error']['Code'] == 'InvalidParameterException':
                    raise ClientInvalidParameterError
            else:
                raise ClientExError   
        else:
            response.pop("ResponseMetadata", None)
            return response