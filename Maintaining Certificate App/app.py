from flask import Flask, request, jsonify, send_from_directory
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder=".", static_url_path="")

# MongoDB connection
client = MongoClient(f"mongodb://{os.getenv('DBuser')}:{os.getenv('DBpassword')}@{os.getenv('DBip')}:27017/")
db = client[os.getenv('DBname')]
collection = db[os.getenv('CollectionName')]

@app.route('/')
def index():
    return send_from_directory('.', 'index3.html')

@app.route('/search', methods=['GET'])
def search_certificate():
    dns = request.args.get('dns')
    result = collection.find_one({"dns": dns}, {"_id": 0})
    return jsonify(result) if result else jsonify({"error": "Not found"})

@app.route('/add', methods=['POST'])
def add_certificate():
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Normalize and set defaults
    data.setdefault("fqdn", "")
    data.setdefault("dns", "")
    data.setdefault("ip", "")
    data.setdefault("local", "")
    data.setdefault("method", "")
    data.setdefault("pickup-ID", "")
    data.setdefault("state", "")
    data.setdefault("Country", "IL")
    data.setdefault("cert_location", "")
    data.setdefault("host_user", "")
    data.setdefault("host_password", "IL")

    # Normalize Country to uppercase
    if "Country" in data and isinstance(data["Country"], str):
        data["Country"] = data["Country"].strip().upper()

    result = collection.insert_one(data)
    return jsonify({"message": "Certificate added", "id": str(result.inserted_id)})

@app.route('/update', methods=['POST'])
def update_certificate():
    data = request.json
    print("Incoming update payload:", data)  # Debug logging

    fqdn = data.pop("fqdn", None)
    cert_id = data.pop("id", None)

    if not fqdn and not cert_id:
        return jsonify({"error": "FQDN or ID required"}), 400

    # Normalize Country if present
    if "Country" in data and isinstance(data["Country"], str):
        data["Country"] = data["Country"].strip().upper()

    query = {}
    if fqdn:
        query["fqdn"] = fqdn
    if cert_id:
        try:
            query["_id"] = ObjectId(cert_id)
        except Exception as e:
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
def delete_certificate():
    data = request.json
    password = data.get('password')
    if password != os.getenv("SysPassword"):  # Load password from .env
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
def list_certificates():
    results = list(collection.find({}, {}))
    for result in results:
        result["_id"] = str(result["_id"])
        if "host_password" in result:
            result["host_password"] = "******"
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True,port=5555)


