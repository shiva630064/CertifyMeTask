from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

admins = {}  

reset_tokens = {}  

sessions = {}  

# ===== SIGNUP =====
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({"error": "All fields required"}), 400

    if email in admins:
        return jsonify({"error": "Account already exists"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    admins[email] = {
        "name": name,
        "password": generate_password_hash(password)
    }

    return jsonify({"message": "Account created successfully"}), 200


# ===== LOGIN =====
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    remember = data.get('remember', False)

    user = admins.get(email)

    if not user or not check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid email or password"}), 401

    session_token = str(uuid.uuid4())

    expiry = datetime.utcnow() + (timedelta(days=7) if remember else timedelta(hours=1))

    sessions[session_token] = {
        "email": email,
        "expiry": expiry
    }

    return jsonify({
        "message": "Login successful",
        "token": session_token,
        "name": user['name']
    })


# ===== FORGOT PASSWORD =====
@app.route('/api/auth/forgot', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    # Always same response (security requirement)
    if email in admins:
        token = str(uuid.uuid4())
        expiry = datetime.utcnow() + timedelta(hours=1)

        reset_tokens[token] = {
            "email": email,
            "expiry": expiry
        }

        print(f"RESET LINK: http://localhost:5000/reset/{token}")

    return jsonify({"message": "If the email exists, a reset link has been sent."})


# ===== VALIDATE RESET TOKEN =====
@app.route('/api/auth/validate-reset/<token>', methods=['GET'])
def validate_token(token):
    data = reset_tokens.get(token)

    if not data:
        return jsonify({"error": "Invalid token"}), 400

    if datetime.utcnow() > data['expiry']:
        return jsonify({"error": "Token expired"}), 400

    return jsonify({"message": "Token valid"})


# ===== RESET PASSWORD =====
@app.route('/api/auth/reset/<token>', methods=['POST'])
def reset_password(token):
    data = reset_tokens.get(token)

    if not data:
        return jsonify({"error": "Invalid token"}), 400

    if datetime.utcnow() > data['expiry']:
        return jsonify({"error": "Token expired"}), 400

    new_password = request.json.get('password')

    if not new_password or len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    email = data['email']

    admins[email]['password'] = generate_password_hash(new_password)

    del reset_tokens[token]

    return jsonify({"message": "Password reset successful"})


# ===== RUN =====
if __name__ == '__main__':
    app.run(debug=True)