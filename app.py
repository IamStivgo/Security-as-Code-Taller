import ast
import operator
import os
import hmac
import datetime
import functools

import bcrypt
import jwt
from flask import Flask, jsonify, request
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ✅ Clave secreta desde variable de entorno — usada para firmar JWTs
SECRET_KEY = os.environ["SECRET_KEY"]

# ✅ Debug desactivado por defecto
app.debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

# ✅ Contraseñas almacenadas como hashes bcrypt (nunca en texto plano)
users = {
    "admin":   bcrypt.hashpw(os.environ["USER_ADMIN_PASSWORD"].encode(),   bcrypt.gensalt()),
    "cliente": bcrypt.hashpw(os.environ["USER_CLIENTE_PASSWORD"].encode(), bcrypt.gensalt()),
}


# ---------------------------------------------------------------------------
# Decorador: valida el JWT en el header Authorization: Bearer <token>
# ---------------------------------------------------------------------------
def token_required(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Token requerido"}), 401

        token = auth_header.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.current_user = payload["sub"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido"}), 401

        return func(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Calculadora segura — reemplaza eval() con AST restringido
# Solo permite: +  -  *  /  //  **  números y paréntesis
# ---------------------------------------------------------------------------
_SAFE_OPS = {
    ast.Add:  operator.add,
    ast.Sub:  operator.sub,
    ast.Mult: operator.mul,
    ast.Div:  operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Pow:  operator.pow,
    ast.USub: operator.neg,
}

def _safe_eval(node):
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _SAFE_OPS:
        return _SAFE_OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _SAFE_OPS:
        return _SAFE_OPS[type(node.op)](_safe_eval(node.operand))
    raise ValueError(f"Operación no permitida: {ast.dump(node)}")


# ---------------------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    stored_hash = users.get(username)

    # ✅ bcrypt.checkpw realiza comparación segura (timing-safe + hash)
    if stored_hash and bcrypt.checkpw(password.encode(), stored_hash):
        # ✅ JWT dinámico: único por sesión, firmado, con expiración de 1 hora
        payload = {
            "sub": username,
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return jsonify({"message": "Login exitoso", "token": token})

    return jsonify({"error": "Credenciales inválidas"}), 401


@app.route("/admin")
@token_required  # ✅ Solo accesible con JWT válido
def admin():
    return jsonify({"secret": "TOP_SECRET", "user": request.current_user})


@app.route("/search")
@token_required  # ✅ Requiere JWT válido
def search():
    q = request.args.get("q", "")
    # ✅ Parámetro separado del SQL — nunca concatenado
    query = "SELECT * FROM users WHERE name = ?"
    return jsonify({"query": query, "params": [q]})


@app.route("/calc")
@token_required  # ✅ Requiere JWT válido
def calc():
    expr = request.args.get("expr", "0")
    try:
        # ✅ AST restringido — solo operaciones matemáticas, sin eval()
        tree = ast.parse(expr, mode="eval")
        result = _safe_eval(tree)
        return jsonify({"result": result})
    except (ValueError, ZeroDivisionError, SyntaxError) as e:
        return jsonify({"error": f"Expresión inválida: {e}"}), 400


@app.route("/echo")
@token_required  # ✅ Requiere JWT válido
def echo():
    msg = request.args.get("msg", "")
    # ✅ Retorna JSON con Content-Type correcto — evita XSS reflejado
    return jsonify({"msg": msg})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
