import requests
from flask import request

def fetch_profile():
    profile_url = request.args["profile"]
    return requests.get(profile_url, verify=False).json()
