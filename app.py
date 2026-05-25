import os
from flask import Flask, jsonify, request
from dotenv import load_dotenv

load_dotenv()  # Carga variables desde el archivo .env

app = Flask(__name__)

# ✅ Credenciales leídas desde variables de entorno
users = {
    "admin": os.environ["USER_ADMIN_PASSWORD"],
    "cliente": os.environ["USER_CLIENTE_PASSWORD"],
}

# ✅ Debug desactivado por defecto; solo activo si FLASK_DEBUG=true en .env
app.debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

# ✅ Clave secreta leída desde variable de entorno
SECRET_KEY = os.environ["SECRET_KEY"]


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username in users and users[username] == password:
        return jsonify({
            "message": "Login exitoso",
            # TODO: reemplazar por JWT dinámico con expiración
            "token": "autenticado"
        })

    return jsonify({"error": "Credenciales inválidas"}), 401


@app.route("/admin")
def admin():
    return jsonify({"secret": "TOP_SECRET"})


@app.route("/search")
def search():
    q = request.args.get("q", "")
    query = "SELECT * FROM users WHERE name = '" + q + "'"
    return jsonify({"query": query})


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    result = eval(expr)
    return jsonify({"result": result})


@app.route("/echo")
def echo():
    msg = request.args.get("msg")
    return msg


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)