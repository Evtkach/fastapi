from pydantic_settings import BaseSettings

from database import AsyncSessionLocal


class Settings(BaseSettings):
    """Application settings."""
    APP_NAME: str = "FastAPI Auth Examples"
    DEBUG: bool = False
    API_USERNAME: str = "admin"
    API_PASSWORD: str = "password"

    class Config:
        env_file = ".env"


settings = Settings()


# Настройки для отправки почты (в реальном проекте берите из .env)
SMTP_USER = "your_email@gmail.com"
SMTP_PASSWORD = "your_app_password"  # Пароль приложения, а не от почты
SMTP_SERVER = "://gmail.com"
SMTP_PORT = 465

# Секрет конкретно для токенов сброса пароля
RESET_PASSWORD_SECRET = "super_secret_recovery_key_123"


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session