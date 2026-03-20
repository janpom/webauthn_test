import base64
import json
import os
from datetime import datetime
from functools import wraps

from fastapi import FastAPI
from pydantic import BaseModel
from starlette.responses import JSONResponse, PlainTextResponse
from webauthn import (generate_authentication_options, generate_registration_options, verify_authentication_response,
    verify_registration_response)
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

app = FastAPI()

# <config>
RP_ID = "webauthn-test-v9su.onrender.com"

# keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android | grep SHA256
ANDROID_APP_SIGN_CERT_FINGERPRINT = "F0:91:76:BC:A6:5F:73:3D:1F:82:86:59:F2:CB:0E:B0:58:8F:FF:1B:27:9E:03:D9:39:A7:6C:11:BC:C7:A7:9C"
# </config>

ENCODED_FINGERPRINT = base64.urlsafe_b64encode(bytes.fromhex(ANDROID_APP_SIGN_CERT_FINGERPRINT.replace(":", ""))).rstrip(b"=").decode()
ORIGIN = f"https://{RP_ID}"
EXPECTED_CLIENT_ORIGINS = [
    ORIGIN,
    f"android:apk-key-hash:{ENCODED_FINGERPRINT}",
]

users = {}
challenges = {}

LOG_ENTRIES = []
MAX_LOG_ENTRIES = 200

class UsernameRequest(BaseModel):
    username: str


class CredentialResponse(BaseModel):
    id: str
    rawId: str
    type: str
    response: dict


def log_endpoint(endpoint_name: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            request_data = None

            for arg in args:
                if hasattr(arg, "dict"):
                    request_data = arg.dict()
                    break

            if request_data is None:
                for value in kwargs.values():
                    if hasattr(value, "dict"):
                        request_data = value.dict()
                        break

            # Call actual endpoint
            response = func(*args, **kwargs)

            # Normalize response (dict or JSONResponse)
            if hasattr(response, "body"):
                try:
                    response_data = json.loads(response.body)
                except Exception:
                    response_data = str(response.body)
            else:
                response_data = response

            # Log entry
            entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "endpoint": endpoint_name,
                "request": request_data,
                "response": response_data,
            }

            LOG_ENTRIES.append(entry)

            if len(LOG_ENTRIES) > MAX_LOG_ENTRIES:
                LOG_ENTRIES.pop(0)

            return response

        return wrapper
    return decorator


@app.post("/register/options")
@log_endpoint("/register/options")
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

    return json.loads(options_to_json(options))


@app.post("/register/verify")
@log_endpoint("/register/verify")
def register_verify(req: CredentialResponse):
    client_data = json.loads(
        b64url_decode(req.response.get("clientDataJSON"))
    )

    challenge = b64url_decode(client_data["challenge"])

    username = None

    for u, ch in challenges.items():
        if ch == challenge:
            username = u
            break

    if not username:
        return {"error": "Unknown challenge"}

    verification = verify_registration_response(
        credential=req.dict(),
        expected_challenge=challenge,
        expected_origin=EXPECTED_CLIENT_ORIGINS,
        expected_rp_id=RP_ID,
    )

    users[username]["credentials"].append({
        "credential_id": verification.credential_id,
        "public_key": verification.credential_public_key,
        "sign_count": verification.sign_count,
    })

    return {"status": "ok"}


@app.post("/auth/options")
@log_endpoint("/auth/options")
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


@app.post("/auth/verify")
@log_endpoint("/auth/verify")
def auth_verify(req: CredentialResponse):
    credential_id = b64url_decode(req.id)

    username = None
    cred = None

    for u, user in users.items():
        for c in user["credentials"]:
            if c["credential_id"] == credential_id:
                username = u
                cred = c
                break
        if cred:
            break

    if not cred:
        return {"error": "Unknown credential"}

    expected_challenge = challenges.get(username)

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
        user_list.append({
            "username": username,
            "credential_ids": list(map(b64url, [c["credential_id"] for c in user.get("credentials", [])]))
        })

    revision = os.getenv("RENDER_GIT_COMMIT", "unknown")

    return {
        "revision": revision,
        "users": user_list
    }


@app.get("/log", response_class=PlainTextResponse)
def get_log():
    lines = []

    for entry in reversed(LOG_ENTRIES):
        lines.append(f"[{entry['timestamp']}] {entry['endpoint']}")

        lines.append("REQUEST:")
        lines.append(json.dumps(entry["request"], indent=2))

        lines.append("RESPONSE:")
        lines.append(json.dumps(entry["response"], indent=2))

        lines.append("-" * 80)

    return "\n".join(lines)


@app.get("/.well-known/assetlinks.json")
@log_endpoint("/.well-known/assetlinks.json")
def assetlinks():
    return JSONResponse([
        {
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "com.nexusgroup.personal.sample",
                "sha256_cert_fingerprints": [
                    ANDROID_APP_SIGN_CERT_FINGERPRINT
                ]
            }
        }
    ])


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)
