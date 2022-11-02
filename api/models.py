from sqlalchemy import Column,String,Integer,ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class User(Base):

    __tablename__='users'
    id = Column(Integer, primary_key=True, index=True)
    username=Column(String,unique=True,index=True)
    email=Column(String,unique=True)
    password=Column(String)

    products = relationship("Product", back_populates="owner")

    def __repr__(self):
        return f'<{self.username}--{self.email}'

class Product(Base):

    __tablename__='products'
    id = Column(Integer, primary_key=True, index=True)
    title=Column(String(100),index=True)
    price=Column(Integer)
    description=Column(String(255))
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="products")

    def __repr__(self):
        return f'<{self.title}--{self.price}>'
