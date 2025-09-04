from models.models import UserLogin, UserDB
from passlib.context import CryptContext
from secrets import compare_digest

crypto_context = CryptContext(schemes = ["sha256_crypt"])

USER_DATABASE = []

# Функция добавление пользователя в БД
def addUser(user : UserLogin):
    user_in_db = UserDB(username = user.username, hashed_password = crypto_context.hash(user.password), role = user.role)
    USER_DATABASE.append(user_in_db)

# Функция получения пользователя из БД
def getUser(username : str):
    for user in USER_DATABASE:
        if compare_digest(username, user.username):
            return user
    return None

