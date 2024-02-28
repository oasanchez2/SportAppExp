from .base_command import BaseCommannd
from ..session import Session, engine
from ..models.model import Base

class Reset(BaseCommannd):  
  def execute(self):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(engine)