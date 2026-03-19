import base64
import json

from fastapi import FastAPI
from pydantic import BaseModel
from starlette.responses import JSONResponse
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

import os

app = FastAPI()

# ---------------------------
# CONFIG (IMPORTANT)
# ---------------------------
# 👉 CHANGE THIS to your machine IP
RP_ID = "webauthn-test-v9su.onrender.com"
ORIGIN = f"https://{RP_ID}"
EXPECTED_CLIENT_ORIGINS = [
    ORIGIN,
    "android:apk-key-hash:8JF2vKZfcz0fgoZZ8ssOsFiP_xsnngPZOadsEbzHp5w",
]

# ---------------------------
# In-memory storage (PoC only)
# ---------------------------
users = {}
challenges = {}

# ---------------------------
# Models
# ---------------------------
class UsernameRequest(BaseModel):
    username: str


class CredentialResponse(BaseModel):
    id: str
    rawId: str
    type: str
    response: dict


# ---------------------------
# REGISTER OPTIONS
# ---------------------------
@app.post("/register/options")
def register_options(req: UsernameRequest):
    username = req.username

    if username not in users:
        users[username] = {
            "id": os.urandom(16),
            "credentials": []
        }

    user = users[username]

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name="Test App",
        user_id=user["id"],
        user_name=username,
    )

    challenges[username] = options.challenge

    # ✅ IMPORTANT: convert to JSON-safe format
    return json.loads(options_to_json(options))


# ---------------------------
# REGISTER VERIFY
# ---------------------------
@app.post("/register/verify")
def register_verify(req: CredentialResponse):
    username = "testuser123"  # PoC simplification

    print("REGISTER VERIFY INPUT:", req.dict())

    expected_challenge = challenges.get(username)

    verification = verify_registration_response(
        credential=req.dict(),
        expected_challenge=expected_challenge,
        expected_origin=EXPECTED_CLIENT_ORIGINS,
        expected_rp_id=RP_ID,
    )

    users[username]["credentials"].append({
        "credential_id": verification.credential_id,
        "public_key": verification.credential_public_key,
        "sign_count": verification.sign_count,
    })

    return {"status": "ok"}


# ---------------------------
# AUTH OPTIONS
# ---------------------------
@app.post("/auth/options")
def auth_options(req: UsernameRequest):
    username = req.username

    user = users.get(username)
    if not user:
        return {"error": "User not found"}

    allow_credentials = [
        PublicKeyCredentialDescriptor(id=cred["credential_id"])
        for cred in user["credentials"]
    ]

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
    )

    challenges[username] = options.challenge

    return json.loads(options_to_json(options))


# ---------------------------
# AUTH VERIFY
# ---------------------------
@app.post("/auth/verify")
def auth_verify(req: CredentialResponse):
    username = "testuser123"

    print("AUTH VERIFY INPUT:", req.dict())

    expected_challenge = challenges.get(username)
    user = users.get(username)

    if not user or not user["credentials"]:
        return {"error": "No credentials"}

    cred = user["credentials"][0]

    verification = verify_authentication_response(
        credential=req.dict(),
        expected_challenge=expected_challenge,
        expected_origin=EXPECTED_CLIENT_ORIGINS,
        expected_rp_id=RP_ID,
        credential_public_key=cred["public_key"],
        credential_current_sign_count=cred["sign_count"],
    )

    cred["sign_count"] = verification.new_sign_count

    return {"status": "ok"}


@app.get("/")
def home():
    user_list = []

    for username, user in users.items():
        for cred in user.get("credentials", []):
            user_list.append({
                "username": username,
                "credential_id": b64url(cred["credential_id"])
            })

    revision = os.getenv("RENDER_GIT_COMMIT", "unknown")

    return {
        "revision": revision,
        "users": user_list
    }


@app.get("/.well-known/assetlinks.json")
def assetlinks():
    return JSONResponse([
        {
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "com.nexusgroup.personal.sample",
                "sha256_cert_fingerprints": [
                    "F0:91:76:BC:A6:5F:73:3D:1F:82:86:59:F2:CB:0E:B0:58:8F:FF:1B:27:9E:03:D9:39:A7:6C:11:BC:C7:A7:9C"
                ]
            }
        }
    ])


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
