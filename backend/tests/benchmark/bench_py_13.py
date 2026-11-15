import random

def issue_reset_code():
    reset_code = random.randint(100000, 999999)
    return str(reset_code)
