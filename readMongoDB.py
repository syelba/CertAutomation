from flask import Flask, request, jsonify, send_from_directory
from pymongo import MongoClient
import os
from dotenv import load_dotenv
from bson import ObjectId  # To handle ObjectId for deletion

load_dotenv()

app = Flask(__name__, static_folder=".", static_url_path="")

client = MongoClient(f"mongodb://{os.getenv('DBuser')}:{os.getenv('DBpassword')}@{os.getenv('DBip')}:27017/")
db = client[os.getenv('DBname')]
collection = db[os.getenv('CollectionName')]

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

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
    # Add missing default values for some fields if not provided
    data.setdefault("fqdn", "")
    data.setdefault("dns", "")
    data.setdefault("ip", "")
    data.setdefault("local", "")
    data.setdefault("method", "")
    data.setdefault("pickup-ID", "")
    data.setdefault("state", "")
    data.setdefault("country", "IL")  # Default country if not provided

    result = collection.insert_one(data)
    return jsonify({"message": "Certificate added", "id": str(result.inserted_id)})

@app.route('/update', methods=['POST'])
def update_certificate():
    data = request.json
    fqdn = data.pop("fqdn", None)
    cert_id = data.pop("id", None)

    if not fqdn and not cert_id:
        return jsonify({"error": "FQDN or ID required"}), 400
    
    query = {}
    if fqdn:
        query["fqdn"] = fqdn
    if cert_id:
        try:
            query["_id"] = ObjectId(cert_id)
        except:
            return jsonify({"error": "Invalid ObjectId format"}), 400
    
    if not data:
        return jsonify({"error": "No update fields provided"}), 400  # Prevent empty updates
    
    result = collection.update_one(query, {"$set": data})
    if result.matched_count > 0:
        return jsonify({"message": "Certificate updated"})
    else:
        return jsonify({"error": "Certificate not found"}), 404

@app.route('/delete', methods=['POST'])
def delete_certificate():
    data = request.json
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
    results = list(collection.find({}, {}))  # Fetch all fields
    for result in results:
        result["_id"] = str(result["_id"])  # Convert ObjectId to string
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
