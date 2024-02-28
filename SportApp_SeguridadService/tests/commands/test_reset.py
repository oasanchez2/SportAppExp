from src.commands.reset import Reset
from src.session import Session, engine
from src.models.model import Base

class TestGetOffers():
  def setup_method(self):
    Base.metadata.create_all(engine)
    self.session = Session()

  def test_reset(self):
    Reset().execute()
    assert True

  def teardown_method(self):
    self.session.close()
    Base.metadata.drop_all(bind=engine)