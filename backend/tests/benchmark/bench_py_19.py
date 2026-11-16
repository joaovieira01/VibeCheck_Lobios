import requests
from urllib.parse import urlparse

def fetch_catalog(url):
    if urlparse(url).hostname not in {"catalog.example.test"}:
        raise ValueError("Host not allowed")
    return requests.get(url, timeout=3).json()
