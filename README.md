# webauthn_test

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