from flask import Flask

app = Flask(__name__)

@app.delete("/accounts/<int:account_id>")
def remove_account(account_id):
    Account.query.filter_by(id=account_id).delete()
    return "", 204
