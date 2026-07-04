import pytest
from fastapi import status
from fastapi.testclient import TestClient
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
import jwt

from main import app
import auth
from config import settings

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