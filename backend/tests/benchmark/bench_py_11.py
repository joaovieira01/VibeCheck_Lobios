import logging

def reject_login(email, password):
    logging.warning("Rejected login for %s with password %s", email, password)
