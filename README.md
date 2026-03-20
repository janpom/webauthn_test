# webauthn_test

## Setup

Change the "config" part in server.py.

If the server is to be used with an Android app, set ANDROID_APP_SIGN_CERT_FINGERPRINT.

## Deploy

```
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8000
```

## Endpoints

### State, logs

- / (home) - revision number, list of users
- /log - incoming requests, outgoing response

### WebAuthN

- /register/options
- /register/verify
- /auth/options
- /auth/verify