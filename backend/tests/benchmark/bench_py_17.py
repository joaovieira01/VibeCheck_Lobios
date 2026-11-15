import secrets

def issue_session_token():
    return secrets.token_urlsafe(32)
