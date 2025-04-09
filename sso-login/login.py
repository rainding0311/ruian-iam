import logging
import mysql.connector
import bcrypt
import jwt
import secrets
import datetime
from flask import Flask, request, jsonify

# Configure Flask app
app = Flask(__name__)
app.config["SECRET_KEY"] = "your_super_secret_key"  # Only for HS256 signing
app.config["ACCESS_TOKEN_EXPIRY_HOURS"] = 1  # 1 小时有效
app.config["REFRESH_TOKEN_EXPIRY_DAYS"] = 7  # 7 天有效

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Connect to MySQL
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="$Qwe907806997",
    database="oauth2_db"
)
cursor = db.cursor()

# 1️⃣ User registration
@app.route('/register', methods=['POST'])
def register():
    logger.debug("Request received at /register endpoint")
    
    # Get request data
    data = request.json
    logger.debug(f"Request Data: {data}")

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        logger.debug('Username or password is missing')
        return jsonify({"error": "Username and password cannot be empty"}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    logger.debug(f"Hashed password: {hashed_password}")

    try:
        # Insert data into the database
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed_password))
        db.commit()
        logger.debug('User registered successfully')
        return jsonify({"message": "Registration successful"}), 201
    except mysql.connector.errors.IntegrityError as e:
        logger.error(f"Error: {e}")
        return jsonify({"error": "Username already exists"}), 400
    except mysql.connector.Error as err:
        logger.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500

# 2️⃣ User login (returns JWT Token)
@app.route('/token', methods=['POST'])
def token():
    data = request.json
    grant_type = data.get("grant_type")

    # --- 登录获取 token ---
    if grant_type == "password":
        username = data.get("username")
        password = data.get("password")

        cursor.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode(), user[1].encode()):
            user_id = user[0]

            access_token = generate_access_token(user_id)
            refresh_token = generate_refresh_token(user_id)

            return jsonify({"access_token": access_token, "refresh_token": refresh_token})

        return jsonify({"error": "Invalid username or password"}), 401

    # --- 使用 refresh_token 刷新 access_token ---
    elif grant_type == "refresh_token":
        refresh_token = data.get("refresh_token")

        if not refresh_token:
            return jsonify({"error": "Refresh token is required"}), 400

        cursor.execute("SELECT user_id, expiry, revoked FROM refresh_tokens WHERE token = %s", (refresh_token,))
        token_record = cursor.fetchone()

        if not token_record:
            return jsonify({"error": "Invalid refresh token"}), 401

        user_id, expiry, revoked = token_record

        if revoked:
            return jsonify({"error": "Refresh token has been revoked"}), 401

        if datetime.datetime.utcnow() > expiry:
            return jsonify({"error": "Refresh token has expired"}), 401

        new_access_token = generate_access_token(user_id)
        return jsonify({"access_token": new_access_token})

    return jsonify({"error": "Invalid grant_type"}), 400

# 生成 access token
def generate_access_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=app.config["ACCESS_TOKEN_EXPIRY_HOURS"])
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

# 生成 refresh token（非 JWT）
def generate_refresh_token(user_id):
    refresh_token = secrets.token_hex(32)
    expiry_time = datetime.datetime.utcnow() + datetime.timedelta(days=app.config["REFRESH_TOKEN_EXPIRY_DAYS"])
    cursor.execute("INSERT INTO refresh_tokens (user_id, token, expiry, revoked) VALUES (%s, %s, %s, %s)", 
                   (user_id, refresh_token, expiry_time, False))
    db.commit()
    return refresh_token

# 3️⃣ Authenticate JWT Token (get user information)
@app.route('/userinfo', methods=['GET'])
def userinfo():
    logger.debug('Received request at /userinfo endpoint')

    token = request.headers.get("Authorization")
    if not token:
        logger.debug('No token provided')
        return jsonify({"error": "Token not provided"}), 401
    
    try:
        token = token.split("Bearer ")[-1]
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        logger.debug(f"Token payload: {payload}")
        return jsonify({"user_id": payload["user_id"], "username": payload["username"]})
    except jwt.ExpiredSignatureError:
        logger.error('Token has expired')
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        logger.error('Invalid token')
        return jsonify({"error": "Invalid token"}), 401
    
# 4️⃣ Revoke Refresh Token
@app.route('/revoke', methods=['POST'])
def revoke_token():
    data = request.json
    refresh_token = data.get("refresh_token")

    if not refresh_token:
        return jsonify({"error": "Refresh token is required"}), 400

    cursor.execute("UPDATE refresh_tokens SET revoked = TRUE WHERE token = %s", (refresh_token,))
    db.commit()

    return jsonify({"message": "Refresh token has been revoked"})


if __name__ == "__main__":
    try:
        db.ping()  # Check if the database connection is working
    except mysql.connector.Error as err:
        logger.error(f"Database connection failed: {err}")
        exit(1)

    logger.info("Starting Flask server...")
    app.run(host='0.0.0.0', port=5001, debug=True)