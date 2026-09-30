import os
from typing import Dict

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt


ALGORITHM = "HS256"
security_scheme = HTTPBearer(auto_error=False)


def _require_secret_key() -> str:
    secret_key = os.environ.get("SECRET_KEY", "")
    if not secret_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SECRET_KEY is not configured",
        )
    return secret_key


def get_current_claims(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> Dict[str, object]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        return jwt.decode(
            credentials.credentials,
            _require_secret_key(),
            algorithms=[ALGORITHM],
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def get_current_tenant(
    claims: Dict[str, object] = Depends(get_current_claims),
) -> str:
    tenant_id = claims.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="tenant_id claim is required",
        )
    return tenant_id
