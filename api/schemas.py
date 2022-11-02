from pydantic import BaseModel


class UserRegister(BaseModel):
    id:int
    username:str
    email:str
    password:str

    class Config:
        orm_mode=True
        schema_extra={
            "example":{
                "id":1,
                "username":"test",
                "email":"test@gmail.com",
                "password":"password"
            }
        }

class UserLogin(BaseModel):
    username:str
    password:str

    class Config:
        orm_mode=True

class ProductSchema(BaseModel):
    id:int
    title:str
    price:int
    description:str

    class Config:
        orm_mode=True
        schema_extra={
            "example":{
                "id":1,
                "title":"First Product",
                "price":1000,
                "description":"This is a First Product"
            }
        }

class ProductUpdateSchema(BaseModel):
    title:str|None
    price:int|None
    description:str|None

    class Config:
        orm_mode=True