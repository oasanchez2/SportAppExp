from .base_command import BaseCommannd
from ..models.user import User, UserJsonSchema
from ..session import Session
from ..errors.errors import Unauthorized, IncompleteParams,GetUserNotFoundError,ExeptionExError
from datetime import datetime
import boto3
import os
from botocore.exceptions import ClientError

class GetUser(BaseCommannd):
  def __init__(self, token = None):
    if token == None or token == "":
      raise IncompleteParams()
    else:
      self.token = self.parse_token(token)
  
  def execute(self):
    session = Session()
    
    # Configurar cliente de Cognito
    client = boto3.client('cognito-idp', region_name='us-east-1')

    try:
        response = client.get_user(
            AccessToken= self.token
        )
        user_attributes = response['UserAttributes']
        '''
        for attribute in user_attributes:
            print(attribute['Name'] + ": " + attribute['Value'])
        '''
        return response
    except ClientError as err:       
        print(f"Here's why: {err.response['Error']['Code']}: {err.response['Error']['Message']}")
        if err.response['Error']['Code'] == 'UserNotFoundException':
           raise GetUserNotFoundError
        else:
           raise ExeptionExError
  
  def parse_token(self, token):
    return token.split(' ')[1]