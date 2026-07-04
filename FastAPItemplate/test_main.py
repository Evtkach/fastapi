from datetime import datetime, timezone, timedelta

import pytest
from fastapi import HTTPException
from fastapi import status
from fastapi.testclient import TestClient

import auth
from config import settings
from main import app
from models import ChangePasswordSchema, UserRegisterSchema, ResetPasswordSchema

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_blacklist():
    auth.blacklisted_tokens.clear()


# auth

def test_validate_credentials_success():
    assert auth.validate_credentials(settings.API_USERNAME, settings.API_PASSWORD) is True


def test_validate_credentials_failure():
    assert auth.validate_credentials(username = "wrong_user",password = "wrong_pass") is False


def test_get_jwt_secret_key():
    key = auth.get_jwt_secret_key()
    assert key is not None
    assert isinstance(key, str)
    assert auth.get_jwt_secret_key() == key


def test_create_and_decode_jwt_token():
    username = "test_user"
    token = auth.create_jwt_token(username)

    payload = auth.decode_jwt_token(token)
    assert payload["sub"] == username
    assert "exp" in payload
    assert "iat" in payload
    assert "jti" in payload


def test_decode_expired_token():
    # create expired token
    expires_delta = timedelta(minutes=-10)
    token = auth.create_jwt_token(username = "test_user", expires_delta = expires_delta)


    with pytest.raises(HTTPException) as exc_info:
        auth.decode_jwt_token(token)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Token has expired"


def test_decode_invalid_token():
    with pytest.raises(HTTPException) as exc_info:
        auth.decode_jwt_token("token")

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Invalid token"


# endpoints

def test_health_and_readiness_checks():
    response = client.get("/health")
    assert response.status_code == 200

    response = client.get("/readiness_check")
    assert response.status_code == 200


def test_login_success():
    payload = {
        "username": settings.API_USERNAME,
        "password": settings.API_PASSWORD
    }
    response = client.post("/login", json=payload)
    assert response.status_code == status.HTTP_200_OK

    assert response.json()["username"] == settings.API_USERNAME
    assert response.json()["token_type"] == "bearer"


def test_login_wrong_credentials():
    payload = {
        "username": settings.API_USERNAME,
        "password": "wrong_password"
    }
    response = client.post("/login", json=payload)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid username or password" in response.json()["detail"]


def test_protected_route_without_token():
    response = client.get("/protected")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_protected_route_with_valid_token():
    # login
    login_payload = {"username": settings.API_USERNAME, "password": settings.API_PASSWORD}
    login_res = client.post("/login", json=login_payload)
    token = login_res.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/protected", headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["authenticated_user"] == settings.API_USERNAME


def test_get_me_endpoint():
    token = auth.create_jwt_token("admin_user")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/me", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["username"] == "admin_user"



def test_logout_and_token_revocation():
    token = auth.create_jwt_token(settings.API_USERNAME)
    headers = {"Authorization": f"Bearer {token}"}

    response_before = client.get("/protected", headers=headers)
    assert response_before.status_code == status.HTTP_200_OK

    logout_response = client.post("/logout", headers=headers)
    assert logout_response.status_code == status.HTTP_200_OK
    assert logout_response.json()["message"] == "Logout successful"

    assert token in auth.blacklisted_tokens

    response_after = client.get("/protected", headers=headers)
    assert response_after.status_code == status.HTTP_401_UNAUTHORIZED
    assert response_after.json()["detail"] == "Token has been revoked"


def test_cleanup_expired_blacklisted_tokens():
    now = datetime.now(timezone.utc)

    live_token = "live.token.mock"
    expired_token = "expired.token.mock"

    auth.blacklisted_tokens[live_token] = now + timedelta(minutes=10)
    auth.blacklisted_tokens[expired_token] = now - timedelta(minutes=10)

    auth.cleanup_expired_blacklisted_tokens()

    assert live_token in auth.blacklisted_tokens
    assert expired_token not in auth.blacklisted_tokens


from polyfactory.factories.pydantic_factory import ModelFactory


class ChangePasswordFactory(ModelFactory[ChangePasswordSchema]):
    __model__ = ChangePasswordSchema

# В самом тесте генерируем валидный payload
def test_password_payload():
    # Создаст объект, где старый пароль "secret", а новый сгенерируется случайно
    payload = ChangePasswordFactory.build(old_password="secret")
    assert len(payload.new_password) >= 8



# Создаем фабрику для схемы регистрации
class RegisterFactory(ModelFactory[UserRegisterSchema]):
    __model__ = UserRegisterSchema


def test_registration_success():
    # Генерируем случайного валидного пользователя (случайное имя, валидный email, длинный пароль)
    random_user = RegisterFactory.build()
    payload = random_user.model_dump()

    response = client.post("/auth/register", json=payload)

    # Проверяем успешный статус ответа 201 Created
    assert response.status_code == 201

    # Проверяем структуру ответа (пароля в ответе быть не должно!)
    data = response.json()
    assert "id" in data
    assert data["email"] == payload["email"]
    assert "password" not in data


def test_registration_duplicate_email():
    # Генерируем данные
    user_data = RegisterFactory.build().model_dump()

    # Первый запрос — успешный
    client.post("/auth/register", json=user_data)

    # Второй запрос с тем же email — должен выдать ошибку 400
    response = client.post("/auth/register", json=user_data)
    assert response.status_code == 400
    assert response.json()["detail"] == "Пользователь с таким email уже зарегистрирован"


class ResetPasswordFactory(ModelFactory[ResetPasswordSchema]):
    __model__ = ResetPasswordSchema


def test_reset_password_endpoint():
    # 1. Генерируем валидный токен для теста
    valid_token = auth.create_jwt_token("test@example.com")

    # 2. Создаем payload с помощью фабрики polyfactory
    payload = ResetPasswordFactory.build(token=valid_token).model_dump()

    # 3. Используем client! Отправляем реальный запрос к тестовому API
    response = client.post("/auth/reset-password", json=payload)

    # 4. Проверяем результат (если пользователя нет в БД, ожидаем ошибку 404)
    assert response.status_code == 404
    assert response.json()["detail"] == "Пользователь не найден"