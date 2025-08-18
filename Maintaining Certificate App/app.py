from flask import Flask, request, jsonify, send_from_directory, redirect, url_for, session, render_template, flash
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
import os
from functools import wraps
import bcrypt
from bson.binary import Binary
import subprocess



def get_ssl_expiry(domain, port=443):
    cmd = f"""
    data=$(echo | openssl s_client -servername {domain} -connect {domain}:{port} 2>/dev/null | openssl x509 -noout -enddate | sed -e 's#notAfter=##')
    ssldate=$(date -d \"${{data}}\" '+%s')
    nowdate=$(date '+%s')
    diff=$((ssldate - nowdate))
    echo $((diff / 86400))
    """
    try:
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
        if result.returncode == 0:
            return int(result.stdout.strip())
        else:
            return -1
    except Exception as e:
        return -1




# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder=".", static_url_path="", template_folder=".")

# Secret key for session management (change this in production!)
app.secret_key = os.getenv('flask_sec')

# Secure session cookies
app.config.update(
    SESSION_COOKIE_SECURE=True,       # Use HTTPS in production
    SESSION_COOKIE_HTTPONLY=True,     # Prevent JavaScript access
    SESSION_COOKIE_SAMESITE='Lax'     # Mitigate CSRF risks
)

# MongoDB connection
client = MongoClient(f"mongodb://{os.getenv('DBuser')}:{os.getenv('DBpassword')}@{os.getenv('DBip')}:27017/")
db = client[os.getenv('DBname')]
collection = db[os.getenv('CollectionName')]


# User/Auth DB (local)
auth_client = MongoClient("mongodb://localhost:27017/")
auth_db = auth_client["hash_vault"]
auth_users = auth_db["users"]


def check_password(username, input_password):
    user = auth_users.find_one({"username": username})
    if not user:
        return False

    stored_hash = user["password"]
    if isinstance(stored_hash, Binary):
        stored_hash = bytes(stored_hash)

    return bcrypt.checkpw(input_password.encode(), stored_hash)



# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if check_password(username, password):
            session["username"] = username
            session["logged_in"] = True
            flash("Login successful")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password")
            return render_template("login.html",error="Invalid username or password")

    return render_template("login.html")



# Login required decorator
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper





@app.route('/')
@login_required
def index():
    return send_from_directory('.', 'index2.html')

@app.route('/search', methods=['GET'])
@login_required
def search_certificate():
    dns = request.args.get('dns')
    if not dns or not isinstance(dns, str) or len(dns.strip()) == 0:
        return jsonify({"error": "Missing or invalid 'dns' parameter"}), 400

    result = collection.find_one({"dns": dns.strip()})
    if result:
        result["_id"] = str(result["_id"])
        if "host_password" in result:
            result["host_password"] = "******"
        return jsonify(result)
    else:
        return jsonify({"error": "Not found"}), 404

@app.route('/add', methods=['POST'])
@login_required
def add_certificate():
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    data.setdefault("fqdn", "")
    data.setdefault("dns", "")
    data.setdefault("ip", "")
    data.setdefault("local", "")
    data.setdefault("method", "")
    data.setdefault("pickup-ID", "")
    data.setdefault("state", "")
    data.setdefault("Country", "IL")
    data.setdefault("host_user", "")
    data.setdefault("host_password", "")
    data.setdefault("cert_path", "")
    data.setdefault("key", "")
    data.setdefault("rootca", "")
    data.setdefault("approve","")
    if "Country" in data and isinstance(data["Country"], str):
        data["Country"] = data["Country"].strip().upper()

    result = collection.insert_one(data)
    return jsonify({"message": "Certificate added", "id": str(result.inserted_id)})

@app.route('/update', methods=['POST'])
@login_required
def update_certificate():
    data = request.json
    print("Incoming update payload:", data)

    fqdn = data.pop("fqdn", None)
    cert_id = data.pop("id", None)

    if not fqdn and not cert_id:
        return jsonify({"error": "FQDN or ID required"}), 400

    if "Country" in data and isinstance(data["Country"], str):
        data["Country"] = data["Country"].strip().upper()

    query = {}
    if fqdn:
        query["fqdn"] = fqdn
    if cert_id:
        try:
            query["_id"] = ObjectId(cert_id)
        except Exception:
            return jsonify({"error": "Invalid ObjectId format"}), 400

    if not data:
        return jsonify({"error": "No update fields provided"}), 400

    result = collection.update_one(query, {"$set": data})
    print(f"Matched: {result.matched_count}, Modified: {result.modified_count}")

    if result.matched_count > 0:
        return jsonify({"message": "Certificate updated"})
    else:
        return jsonify({"error": "Certificate not found"}), 404

@app.route('/delete', methods=['POST'])
@login_required
def delete_certificate():
    data = request.json
    password = data.get('password')
    if password != os.getenv("SysPassword"):
        return jsonify({"message": "Unauthorized: Incorrect password"})
    try:
        object_id = data['id']
        result = collection.delete_one({"_id": ObjectId(object_id)})
        if result.deleted_count == 1:
            return jsonify({"message": "Certificate deleted successfully"})
        else:
            return jsonify({"error": "Certificate not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/list', methods=['GET'])
@login_required
def list_certificates():
    results = list(collection.find({}, {}))
    for result in results:
        result["_id"] = str(result["_id"])
        if "host_password" in result:
            result["host_password"] = "******"
    return jsonify(results)



# New route for the Certificate Status page
@app.route('/certificate_status_page')
@login_required
def certificate_status_page():
    return send_from_directory('.', 'status.html')

# New API endpoint to get certificate status and expiry
@app.route('/certificate_status', methods=['GET'])
@login_required
def certificate_status():
    results = list(collection.find({}, {"dns": 1}))
    certificate_data = []
    
    for cert in results:
        dns = cert.get("dns")
        if dns:
            days_left = get_ssl_expiry(dns)
            certificate_data.append({
                "dns": dns,
                "days_left": days_left
            })
    
    return jsonify(certificate_data)




if __name__ == '__main__':
    app.run(debug=True, port=5555)
