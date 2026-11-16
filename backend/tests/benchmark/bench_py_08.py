import pickle
from flask import request

def restore_preferences():
    return pickle.loads(request.data)
