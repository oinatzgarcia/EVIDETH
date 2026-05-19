from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, APIKeyHeader
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import User, UserRole, Camera
from app.core.security import decode_token, verify_api_key

bearer_scheme = HTTPBearer()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
