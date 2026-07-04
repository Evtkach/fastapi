import uvicorn
from fastapi.responses import Response
import jwt
from datetime import datetime, timedelta

from models import ErrorMessage, LoginRequest, LoginResponse, ChangePasswordSchema, UserRegisterSchema, \
    ForgotPasswordSchema, UserResponseSchema, ResetPasswordSchema
from auth import get_current_user, create_jwt_token, blacklist_token, validate_credentials, security
from fastapi.security import HTTPAuthorizationCredentials
from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from config import get_db
from models import User
from auth import send_reset_email, verify_reset_token

from salt import verify_password, hash_password

app = FastAPI()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
app = FastAPI()


@app.get("/health")
def health_check():
    return Response(status_code=200)
@app.get("/readiness_check")
def readiness_check():
    return Response(status_code=200)

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"



def generate_token(data: dict):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=15)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

token = generate_token({"sub": "user_id_123"})
print(token)

@app.post(
    "/login",
    response_model=LoginResponse,
    summary="Login with username and password",
    description="Get a JWT access token",
    responses={
        200: {"description": "Login successful"},
        401: {
            "model": ErrorMessage,
            "description": "Unauthorized: Invalid credentials"
        }
    }
)

async def login(login_request: LoginRequest):
    """Login endpoint that returns a JWT access token."""
    # Validate credentials
    if not validate_credentials(login_request.username, login_request.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Create JWT token
    access_token = create_jwt_token(login_request.username)

    return LoginResponse(
        access_token=access_token,
        username=login_request.username
    )


@app.get(
    "/protected",
    summary="Protected route (requires JWT token)",
    description="This endpoint requires a valid JWT token in Authorization header",
    responses={
        200: {"description": "Successful response"},
        401: {
            "model": ErrorMessage,
            "description": "Unauthorized: Invalid or missing token"
        }
    }
)
async def protected_route(username: str = Depends(get_current_user)):
    """Protected route that requires a valid JWT token."""
    return {
        "message": "This is a protected route",
        "data": "secret information accessible with JWT token",
        "authenticated_user": username
    }


@app.post(
    "/logout",
    summary="Logout and blacklist token",
    description="Blacklist the current JWT token to prevent further use",
    responses={
        200: {"description": "Logout successful"},
        401: {
            "model": ErrorMessage,
            "description": "Unauthorized: Invalid or missing token"
        }
    }
)
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Logout endpoint that blacklists the current JWT token."""
    token = credentials.credentials
    blacklist_token(token)

    return {"message": "Logout successful"}


@app.get(
    "/me",
    summary="Get current user info",
    description="Get information about the currently authenticated user",
    responses={
        200: {"description": "User information"},
        401: {
            "model": ErrorMessage,
            "description": "Unauthorized: Invalid or missing token"
        }
    }
)
async def get_user_info(username: str = Depends(get_current_user)):
    """Get current user information from JWT token."""
    return {
        "username": username,
        "message": "User information retrieved successfully"
    }


@app.post("/users/{user_id}/change-password", status_code=status.HTTP_200_OK)
async def change_password(
        user_id: int,
        payload: ChangePasswordSchema,
        db: AsyncSession = Depends(get_db)
):
    # 1. Ищем пользователя в базе данных
    query = select(User).where(User.id == user_id)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )

    # 2. Проверяем, совпадает ли старый пароль с хэшем из БД
    if not verify_password(payload.old_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Неверный старый пароль"
        )

    # 3. Хэшируем новый пароль (bcrypt сгенерирует новую соль)
    user.hashed_password = hash_password(payload.new_password)

    # 4. Сохраняем изменения в базе данных
    await db.commit()

    return {"status": "success", "message": "Пароль успешно изменен"}


@app.post(
    "/auth/register",
    response_model=UserResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Регистрация нового пользователя"
)
async def register_user(
        payload: UserRegisterSchema,
        db: AsyncSession = Depends(get_db)
):
    # 1. Проверяем, существует ли уже пользователь с таким email
    query = select(User).where(User.email == payload.email)
    result = await db.execute(query)
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким email уже зарегистрирован"
        )

    # 2. Хэшируем пароль (соль генерируется автоматически внутри hash_password)
    hashed_pass = hash_password(payload.password)

    # 3. Создаем объект модели SQLAlchemy
    new_user = User(
        name=payload.name,
        email=payload.email,
        hashed_password=hashed_pass
    )

    # 4. Сохраняем в базу данных
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)  # Получаем сгенерированный базой данных ID

    # FastAPI автоматически преобразует модель User в UserResponseSchema
    return new_user


# 1. ЗАПРОС НА ВОССТАНОВЛЕНИЕ (Отправка письма)
@app.post("/auth/forgot-password", status_code=status.HTTP_200_OK)
async def forgot_password(
        payload: ForgotPasswordSchema,
        background_tasks: BackgroundTasks,  # Используем фоновые задачи, чтобы API не зависало на время отправки письма
        db: AsyncSession = Depends(get_db)
):
    query = select(User).where(User.email == payload.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    # Из соображений безопасности лучше всегда отвечать 200 OK,
    # даже если email нет в базе (чтобы хакеры не перебирали базу email)
    if user:
        token = create_jwt_token(user.email)
        # Отправляем письмо в фоне
        background_tasks.add_task(send_reset_email, user.email, token)

    return {"message": "Если email зарегистрирован в системе, письмо для восстановления отправлено."}


# 2. СБРОС И УСТАНОВКА НОВОГО ПАРОЛЯ
@app.post("/auth/reset-password", status_code=status.HTTP_200_OK)
async def reset_password(
        payload: ResetPasswordSchema,
        db: AsyncSession = Depends(get_db)
):
    # Проверяем и декодируем токен
    email = verify_reset_token(payload.token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Токен недействителен или его срок действия истек"
        )

    # Ищем пользователя по извлеченному email
    query = select(User).where(User.id == id)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Пользователь не найден")

    # Хэшируем и сохраняем новый пароль (соль сгенерируется сама внутри bcrypt)
    user.hashed_password = hash_password(payload.new_password)
    await db.commit()

    return {"message": "Пароль успешно обновлен"}