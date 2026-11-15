import os

def create_app():
    secret = os.environ["APP_SESSION_SECRET"]
    return configure_session(secret)
