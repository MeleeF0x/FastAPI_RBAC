from fastapi import FastAPI, HTTPException
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from fastapi import Depends
import app.security as security
from app.rbac import PermissionChecker
from models.models import UserLogin, UserDB
from app.db import addUser, getUser
from slowapi import Limiter
from slowapi.util import get_remote_address

app = FastAPI()
limiter = Limiter(get_remote_address)

app.state.limiter = limiter

async def get_rate_limit_by_role(current_user = Depends(security.getUserFromJWT)) -> str:
    role = current_user.role

    if role == "admin":
        return "1000/minute"
    
    if role == "user":
        return "20/minute"
    
    if role == "guest":
        return "5/minute"
    
@app.get("/")
async def root():
    return {"message" : "Hello Web!"}

@app.post("/registration")
async def user_registration(user : UserLogin):
    if getUser(user.username) is None:
        addUser(user)
        return JSONResponse(status_code = 201, content = {"message" : f"User {user.username} has been created"})
    raise HTTPException(status_code = 409, detail = f"User {user.username} already exist")

@app.post("/login")
async def user_login_auth(user = Depends(security.basicAuth)):
    token_data = {"sub" : user.username}
    jwt_token = security.createJwt(token_data, 5)
    return {"JWT Token" : jwt_token}

@app.get("/admin_endpoint")
@PermissionChecker(["admin"])
@limiter.limit(get_rate_limit_by_role)
async def admin_endpoint(request : Request, current_user : UserDB = Depends(security.getUserFromJWT)):
    return {"message" : "Access granted"}

@app.post("/user_endpoint")
@PermissionChecker(["user"])
@limiter.limit(get_rate_limit_by_role)
async def user_endpoint(request : Request, current_user : UserDB = Depends(security.getUserFromJWT)):
    return {"message" : "Access granted"}

@app.get("/guest_endpoint")
@limiter.limit(get_rate_limit_by_role)
async def guest_endpoint(request : Request, current_user : UserLogin = Depends(security.getUserFromJWT)):
    return {"message" : "Access granted"}