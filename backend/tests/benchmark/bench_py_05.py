from flask import request, render_template_string

def greeting():
    name = request.args.get("name", "")
    return render_template_string(f"<h1>Welcome {name}</h1>")
