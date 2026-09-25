import os
from pymongo import MongoClient
from datetime import datetime
import bcrypt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MongoDB connection string (defaults to local Community Server)
mongo_uri = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/tokenized_asset")

# Connect to MongoDB
client = MongoClient(mongo_uri)

# Select database
db = client["tokenized_asset"]

# Select collections
users_collection = db["users"]
assets_collection = db["assets"]  # Stores fully minted tokens
upload_collection = db["upload"]  # Stores uploaded files before minting

# 🔹 Insert User Data
def insert_user(username, full_name, email, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user_data = {
        "username": username,  # New field added
        "full_name": full_name, 
        "email": email,
        "password": hashed_password
    }
    result = users_collection.insert_one(user_data)
    print(f"✅ User inserted with ID: {result.inserted_id}")

# 🔹 Insert Upload Data (Before Tokenization)
def insert_upload(serial_no, cid, file_name, user_email):
    """
    Store uploaded document details, including who uploaded it (username + email).
    """
    user = users_collection.find_one({"email": user_email})
    if not user:
        print(f"❌ User {user_email} not found in database.")
        return False
    
    upload_data = {
        "serial_no": serial_no,
        "cid": cid,
        "file_name": file_name,
        "upload_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "uploaded_by_email": user_email,  # Store email
        "uploaded_by_username": user["username"]  # Store username
    }
    result = upload_collection.insert_one(upload_data)
    print(f"📝 File '{file_name}' uploaded by {user['username']} ({user_email}) with ID: {result.inserted_id}")

# 🔹 Move Data from Upload → Assets After Tokenization
def move_to_assets(serial_no, cid, block_no, contract_address, user_email):
    """
    Move a file from the 'upload' collection to 'assets' only if it belongs to the logged-in user.
    """
    upload_data = upload_collection.find_one({"serial_no": serial_no, "cid": cid, "uploaded_by_email": user_email})

    if not upload_data:
        print(f"⚠️ No matching upload found for CID: {cid} or not uploaded by {user_email}")
        return False  # Prevent unauthorized minting

    # Prevent minting already tokenized files
    existing_token = assets_collection.find_one({"cid": cid})
    if existing_token:
        print(f"❌ This file is already minted (CID: {cid})")
        return False

    asset_data = {
        "serial_no": serial_no,
        "cid": cid,
        "file_name": upload_data["file_name"],
        "upload_date": upload_data["upload_date"],
        "uploaded_by_email": user_email,  
        "uploaded_by_username": upload_data["uploaded_by_username"],  # Keep username in assets
        "block_no": block_no,
        "contract_address": contract_address
    }

    assets_collection.insert_one(asset_data)  # Move to assets
    upload_collection.delete_one({"serial_no": serial_no, "cid": cid})  # Remove from upload
    print(f"✅ File '{upload_data['file_name']}' minted by {upload_data['uploaded_by_username']} ({user_email}) with contract: {contract_address}")
    return True  # Successful minting

# Close the MongoDB connection
client.close()
