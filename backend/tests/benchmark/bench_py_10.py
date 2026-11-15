import subprocess
from flask import request

def convert():
    image = request.form["image"]
    return subprocess.check_output(f"convert {image} /tmp/output.png", shell=True)
