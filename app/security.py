from fastapi import Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer
from passlib.context import CryptContext
from models.models import UserLogin
from app.db import getUser
import jwt
from datetime import datetime, timedelta

security = HTTPBasic()
crypt_context = CryptContext(schemes=["sha256_crypt"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl = "login")

SECRET_KEY = "ABSOLUTELYSECRETKEYTELLNOONE"
ALGHORITM = "HS256"

def basicAuth(credentials : HTTPBasicCredentials = Depends(security)):
    user_in_db = getUser(credentials.username)
    if user_in_db is None:
        raise HTTPException(status_code = 404, detail = "User not found")
    if not crypt_context.verify(credentials.password, user_in_db.hashed_password):
        raise HTTPException(status_code = 401, headers = {"WWW-Authenticate" : "Basic"})
    return user_in_db

def createJwt(payload : dict, ttl : int):
    current_time_stamp = datetime.now()
    data = dict(exp = (current_time_stamp + timedelta(minutes = ttl)))
    payload.update(data)
    return jwt.encode(payload = payload, key = SECRET_KEY, algorithm = ALGHORITM)

def authJWT(token : str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, key = SECRET_KEY, algorithms = [ALGHORITM])
        return payload["sub"]
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code = 401, detail = "Token has been expired", headers = {"WWW-Authenticate" : "Bearer"})
    
    except jwt.InvalidTokenError:
        raise HTTPException(status_code = 401, detail = "Invalid token", headers = {"WWW-Authenticate" : "Bearer"})

def getUserFromJWT(token : str = Depends(oauth2_scheme)):
    try:
        current_user = getUser(authJWT(token))
    
    except HTTPException:
        guest_user = UserLogin(username = "guest", role = "guest", password = "*****")
        current_user = guest_user
    
    if current_user is None:
        guest_user = UserLogin(username = "guest", role = "guest", password = "*****")
        current_user = guest_user

    return current_user
