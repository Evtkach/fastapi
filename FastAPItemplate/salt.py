import bcrypt

def hash_password(password: str) -> str:
    """Генерирует соль и хэширует пароль."""
    # Переводим строку в байты
    password_bytes = password.encode('utf-8')
    # Генерируем соль (по умолчанию 12 раундов)
    salt = bcrypt.gensalt()
    # Хэшируем пароль вместе с солью
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    # Возвращаем строковое представление хэша для хранения в БД
    return hashed_password.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверяет соответствие чистого пароля и хэша из БД."""
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    # bcrypt сам извлечет соль из хэша и сравнит результаты
    return bcrypt.checkpw(password_bytes, hashed_bytes)