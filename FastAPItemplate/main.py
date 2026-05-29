from fastapi import FastAPI, HTTPException, status, Depends, BackgroundTasks
from fastapi.responses import Response
import jwt
from datetime import datetime, timedelta
from models import ErrorMessage, LoginRequest, LoginResponse
from auth import get_current_user, create_jwt_token, blacklist_token, validate_credentials, security
from fastapi.security import HTTPAuthorizationCredentials
app = FastAPI()


@app.get("/health")
def health_check():
    return Response(status_code=200)
@app.get("/readiness_check")
def readiness_check():
    return Response(status_code=200)

# BALANCE = {}
#
# @app.get("/balance")
# def get_balance(wallet_name: str | None = None):
#     if wallet_name is None:
#         return {"total_balance": sum(BALANCE.values())}
#     if wallet_name not in BALANCE:
#         return HTTPException(
#             status_code=404,
#             detail=f"Wallet {wallet_name} not found."
#         )
#     return {"wallet": wallet_name, "balance": BALANCE[wallet_name]}
#
# @app.post("/wallets/{name}")
# def receive_money(name: str, amount: int):
#     if name not in BALANCE:
#         BALANCE[name] = 0
#     BALANCE[name] += amount
#     return {
#         "massage": f"Added {amount} to {name}",
#         "wallet": name,
#         "new_balance": BALANCE[name]
#     }
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"

def generate_token(data: dict):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=15)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

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