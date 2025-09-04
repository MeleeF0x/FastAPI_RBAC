from pydantic import BaseModel, Field

# Базовая модель пользователя
class UserBase(BaseModel):
    username : str
    role : str

# Модель пользователя для базовой аутентификации
class UserLogin(UserBase):
    password : str = Field(min_length = 3)

# Модель пользователя для базы данных
class UserDB(UserBase):
    hashed_password : str
    