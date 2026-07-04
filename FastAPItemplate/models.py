from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from database import Base
from pydantic import BaseModel, EmailStr, Field


class ErrorMessage(BaseModel):
    """Error message model."""
    detail: str


class LoginRequest(BaseModel):
    """Login request model."""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Login response model."""
    access_token: str
    token_type: str = "bearer"
    username: str
    message: str = "Login successful"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    is_active: Mapped[bool] = mapped_column(default=True)
    hashed_password: Mapped[str]

class ChangePasswordSchema(BaseModel):
    old_password: str
    new_password: str = Field(min_length=8, description="Новый пароль должен быть не менее 8 символов")


# Схема, которую присылает клиент при регистрации
class UserRegisterSchema(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, description="Пароль от 8 символов")

# Схема, которую API возвращает клиенту (без пароля!)
class UserResponseSchema(BaseModel):
    id: int
    name: str
    email: EmailStr

class Config:
    from_attributes = True  # Позволяет Pydantic читать данные прямо из ORM-моделей SQLAlchemy


# Этап 1: ввод email
class ForgotPasswordSchema(BaseModel):
    email: EmailStr

# Этап 2: ввод нового пароля
class ResetPasswordSchema(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)