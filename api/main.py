from fastapi import FastAPI,Depends,HTTPException,status
from fastapi_jwt_auth import AuthJWT
from sqlalchemy.orm import Session
from starlette.status import HTTP_401_UNAUTHORIZED
from database import Base,engine,SessionLocal
from schemas import UserRegister,UserLogin,ProductSchema,ProductUpdateSchema
from fastapi.security import HTTPBearer,HTTPAuthorizationCredentials # used to pass data in header 
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import models
from pydantic import BaseModel


Base.metadata.create_all(engine)


app=FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

@app.post('/token',tags=['OAuth'])
async def token(form_data: OAuth2PasswordRequestForm = Depends()):
    return {'access_token' : form_data.username + 'token'}

@app.get('/',tags=['OAuth'])
async def index(token: str = Depends(oauth2_scheme)):
    return {'the_token' : token}

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Settings(BaseModel):
    authjwt_secret_key:str='678cd596107563a5ec1f25e64d13380e07eac222a2d05fabf0c5d61340b86205'

    # to generate authjwt_secret_key use python secrets module
    # import secrets
    # secrets.token_hex()
    # this will generate secret_key
@AuthJWT.load_config
def get_config():
    return Settings()

@app.get("/home",tags=['Home'])
def index():
    return {"message":"Hello"}



# #create a user
@app.post('/signup',response_model=UserRegister,tags=['User'])
async def register(user:UserRegister,db: Session = Depends(get_db)):
    new_user=models.User(username=user.username,email=user.email,password=user.password)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.get('/all_users',tags=['User'])
async def all_users(db: Session = Depends(get_db)):
    users=db.query(models.User).all()
    return users


@app.post('/login',tags=['User'])
async def login(username:str,password:str,db:Session=Depends(get_db),Authorize:AuthJWT=Depends()):
    data=db.query(models.User).filter(models.User.username == username,models.User.password==password).first()
    if data:
        access_token=Authorize.create_access_token(subject=data.username)
        refresh_token=Authorize.create_refresh_token(subject=data.username)
        username=data.username
        return {'username':username,'access_token':access_token,'refresh_token':refresh_token}
    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED,detail="Invalid username or password")


auth_scheme = HTTPBearer()
@app.get('/protected',tags=['JWT Required'])
def get_logged_in_user(db:Session=Depends(get_db),token:HTTPAuthorizationCredentials=Depends(auth_scheme),Authorize:AuthJWT=Depends()):
    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")


    current_user=Authorize.get_jwt_subject()
    user=db.query(models.User).filter(models.User.username==current_user).first()
    email=user.email
    return {"current_user":current_user,'email':email}



@app.get('/new_token',tags=['JWT Required'])
def create_new_token(Authorize:AuthJWT=Depends(),token:HTTPAuthorizationCredentials=Depends(auth_scheme)):

    try:
        Authorize.jwt_refresh_token_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")

    current_user=Authorize.get_jwt_subject()

    access_token=Authorize.create_access_token(subject=current_user)

    return {"new_access_token":access_token}


@app.post('/fresh_login',tags=['User'])
def fresh_login(username:str,password:str,db:Session=Depends(get_db),Authorize:AuthJWT=Depends()):
    data=db.query(models.User).filter(models.User.username == username,models.User.password==password).first()
    if data:
        fresh_token=Authorize.create_access_token(subject=data.username,fresh=True)
        return {"fresh_token":fresh_token}
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid Username or Password")



@app.get('/fresh_url',tags=['JWT Required'])
def get_user(db:Session=Depends(get_db),Authorize:AuthJWT=Depends(),token:HTTPAuthorizationCredentials=Depends(auth_scheme)):
    try:
        Authorize.fresh_jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid Token")

    current_user=Authorize.get_jwt_subject()

    user=db.query(models.User).filter(models.User.username==current_user).first()
    email=user.email
    return {"current_user":current_user,'email':email}

@app.post('/create_product',tags=['Product'],response_model=ProductSchema)
def create_product(product:ProductSchema,db:Session=Depends(get_db),Authorize:AuthJWT=Depends(),token:HTTPAuthorizationCredentials=Depends(auth_scheme)):
    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")

    current_user=Authorize.get_jwt_subject()
    user=db.query(models.User).filter(models.User.username==current_user).first()
    new_product=models.Product(title=product.title,price=product.price,description=product.description,owner_id=user.id)
    db.add(new_product)
    db.commit()
    db.refresh(new_product)
    return new_product


@app.get('/all_products',tags=['Product'])
def get_products(db:Session=Depends(get_db),Authorize:AuthJWT=Depends(),token:HTTPAuthorizationCredentials=Depends(auth_scheme)):
    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")
    current_user=Authorize.get_jwt_subject()
  
    all_products=db.query(models.Product).all()
    return {'all_products':all_products,'current_user':current_user}

@app.get('/single_product',tags=['Product'])
def get_single_product(title:str,db:Session=Depends(get_db),Authorize:AuthJWT=Depends(),token:HTTPAuthorizationCredentials=Depends(auth_scheme)):
    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")

    product=db.query(models.Product).filter(models.Product.title==title).first()
    return product

@app.put('/update_product',response_model=ProductUpdateSchema,tags=['Product'])
def update_product(title:str,product:ProductUpdateSchema,db:Session=Depends(get_db),Authorize:AuthJWT=Depends(),token:HTTPAuthorizationCredentials=Depends(auth_scheme)):
    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")
    
    current_user=Authorize.get_jwt_subject()
    user=db.query(models.User).filter(models.User.username==current_user).first()
    update_product=db.query(models.Product).filter(models.Product.title==title,models.Product.owner_id==user.id).first()
    if update_product:
        update_product.id=update_product.id
        update_product.title=product.title
        update_product.price=product.price
        update_product.description=product.description

        db.commit()
        db.refresh(update_product)
        return update_product
    else:
        return {'Response':'You are not the author of the Product'}


@app.delete('/delete_product',tags=['Product'])
def delete_product(title:str,db:Session=Depends(get_db),Authorize:AuthJWT=Depends(),token:HTTPAuthorizationCredentials=Depends(auth_scheme)):
    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")

    current_user=Authorize.get_jwt_subject()
    user=db.query(models.User).filter(models.User.username==current_user).first()
    delete_product=db.query(models.Product).filter(models.Product.title==title,models.Product.owner_id==user.id).first()
    if delete_product:
        if delete_product is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        print(delete_product)
        db.delete(delete_product)
        db.commit()
        return {'Response':f'{delete_product}\nDeleted SuccessFully'}
    else:
        return {'Response':'You are not the owner of the Product'}