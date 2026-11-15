from functools import wraps
from flask import Flask

app = Flask(__name__)

@app.delete("/records/<int:record_id>")
@login_required
def remove_record(record_id):
    Record.query.filter_by(id=record_id).delete()
    return "", 204
