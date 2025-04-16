from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import jwt
import requests
import os
from datetime import datetime
from web3 import Web3
import subprocess
import solcx
import bcrypt
import re
from pymongo import MongoClient
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

# Load environment variables
load_dotenv()

# ✅ Set Correct Paths for Templates & Static Files
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "backend", "templates"),
    static_folder=os.path.join(BASE_DIR, "backend", "static")  # ✅ Fix the static folder path
)

# ✅ Enable CORS
CORS(app, supports_credentials=True, allow_headers=["Content-Type", "Authorization"])

# ✅ JWT Configuration (✔️ EDITED)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')  
jwt = JWTManager(app)

# ✅ MongoDB Configuration (✔️ EDITED)
mongo_uri = os.getenv("MONGO_URI")  
client = MongoClient(mongo_uri)
db = client["tokenized_asset"]

# ✅ Collections
users_collection = db["users"]
upload_collection = db["upload"]
assets_collection = db["assets"]

# ✅ Blockchain & IPFS Configuration (✔️ All already using env)
IPFS_API_URL = os.getenv('IPFS_API_URL')
RPC_URL = os.getenv('RPC_URL')
PRIVATE_KEY = os.getenv('PRIVATE_KEY')  
GETH_PATH = os.getenv('GETH_PATH')

# ✅ Solidity Contract Source Code
CONTRACT_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "E:/Proof of Authority/blockchain/openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "E:/Proof of Authority/blockchain/openzeppelin/contracts/access/Ownable.sol";

contract CIDToken is ERC721URIStorage, Ownable {
    uint256 private _tokenIdCounter;

    constructor() ERC721("Token", "TOKEN") Ownable() {
        _tokenIdCounter = 0;
    }

    function mintToken(string memory metadataCID) public onlyOwner {
        _tokenIdCounter++;
        uint256 newTokenId = _tokenIdCounter;

        _mint(msg.sender, newTokenId);  // ✅ Assign token to user
        _setTokenURI(newTokenId, metadataCID);  // ✅ Store IPFS CID
    }
}
"""

# ✅ Helper Functions
def start_mining():
    """Start the miner dynamically"""
    print("⛏️ Starting the miner...")
    result = subprocess.run([GETH_PATH, "attach", RPC_URL, "--exec", "miner.start(1)"],
                            capture_output=True, text=True, shell=True)
    print(result.stdout if result.stdout else result.stderr)

def stop_mining():
    """Stop the miner dynamically"""
    print("🛑 Stopping the miner...")
    result = subprocess.run([GETH_PATH, "attach", RPC_URL, "--exec", "miner.stop()"],
                            capture_output=True, text=True, shell=True)
    print(result.stdout if result.stdout else result.stderr)


def compile_solidity_contract(source_code):
    """Compile Solidity contract and return ABI & Bytecode"""
    import solcx

    solcx.install_solc("0.8.20")
    solcx.set_solc_version("0.8.20")

    try:
        compiled_sol = solcx.compile_source(
            source_code,
            output_values=["abi", "bin"],
            allow_paths="E:/Proof of Authority/blockchain/openzeppelin"
        )

        if not compiled_sol:
            raise ValueError("Compilation failed: No output received.")

        # ✅ Dynamically find the correct contract key
        contract_keys = list(compiled_sol.keys())

        if not contract_keys:
            raise ValueError("No contract found in compilation output.")

        contract_key = contract_keys[0]  # Take first key dynamically
        contract_interface = compiled_sol.get(contract_key)

        if not isinstance(contract_interface, dict):
            raise TypeError(f"Unexpected contract interface format: {type(contract_interface)}")

        abi = contract_interface.get("abi")
        bytecode = contract_interface.get("bin")

        if not abi or not bytecode:
            raise ValueError("Compilation failed: ABI or Bytecode is missing.")

        return abi, bytecode

    except Exception as e:
        print("❌ Solidity Compilation Error:", str(e))  # ✅ Print actual error
        return None, None

def deploy_contract(abi, bytecode):
    """Deploy smart contract and return contract address & block number"""
    web3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not web3.is_connected():
        raise Exception("Failed to connect to Ethereum Node")

    account = web3.eth.account.from_key(PRIVATE_KEY)
    contract = web3.eth.contract(abi=abi, bytecode=bytecode)
    nonce = web3.eth.get_transaction_count(account.address, "pending")

    transaction = contract.constructor().build_transaction({
        'from': account.address,
        'gas': 2241176,  # Manually setting gas
        'gasPrice': web3.to_wei('20', 'gwei'),
        'nonce': nonce
    })

    signed_tx = web3.eth.account.sign_transaction(transaction, PRIVATE_KEY)

    start_mining()
    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print("⏳ Waiting for transaction confirmation...")
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    stop_mining()

    return tx_receipt.contractAddress, tx_receipt.blockNumber

# ✅ Serve Frontend Pages
@app.route("/")
def home_page():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

# ✅ User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')

    if not full_name or not email or not password:
        return jsonify({"error": "Full Name, Email, and Password are required"}), 400

    # Validate Email Format (Only Gmail Allowed)
    email_pattern = r"^[a-zA-Z0-9._%+-]+@gmail\.com$"
    if not re.match(email_pattern, email):
        return jsonify({"error": "Only Gmail addresses are allowed"}), 400

    # Check if Email Already Exists
    if users_collection.find_one({"email": email}):
        return jsonify({"error": "Email already exists"}), 400

    # Hash Password & Insert into Database
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users_collection.insert_one({"full_name": full_name, "email": email, "password": hashed_password})

    return jsonify({"message": "User registered successfully"}), 201

# ✅ User Login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        user = users_collection.find_one({"email": email})
        if not user or not bcrypt.checkpw(password.encode(), user["password"].encode()):
            return jsonify({"error": "Invalid credentials"}), 401

        # Store only email in JWT token
        access_token = create_access_token(identity=email)

        print(f"Login successful for user: {email}, token created")  # Debug log

        return jsonify({
            "message": "Login successful",
            "access_token": access_token,
            "user": {"email": email, "full_name": user.get("full_name", "User")}
        }), 200

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


# ✅ Upload File to IPFS
@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    try:
        # Authenticate user
        user_info = get_jwt_identity()
        user_email = user_info.get('email') if isinstance(user_info, dict) else user_info

        # Validate user in DB
        user = users_collection.find_one({"email": user_email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Validate file upload
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        filename = secure_filename(file.filename)

        # Send file to IPFS
        files = {'file': (filename, file.read(), file.mimetype)}
        ipfs_response = requests.post(IPFS_API_URL, files=files)

        if ipfs_response.status_code != 200:
            return jsonify({"error": "IPFS upload failed", "details": ipfs_response.text}), 500

        ipfs_data = ipfs_response.json()
        ipfs_hash = ipfs_data.get("Hash")

        # Store metadata in MongoDB
        upload_data = {
            "cid": ipfs_hash,
            "file_name": filename,
            "description": request.form.get('description', ''),
            "upload_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "uploaded_by_email": user_email,
            "uploaded_by_username": user.get("username", "Unknown")  # Fetch username from DB
        }
        
        upload_collection.insert_one(upload_data)

        return jsonify({
            "message": "File uploaded successfully",
            "cid": ipfs_hash,
            "file_name": filename
        }), 201

    except Exception as e:
        print(f"❌ Upload Error: {str(e)}")  # Keep only essential error log
        return jsonify({"error": str(e)}), 500


# ✅ Mint ERC-721 Token
@app.route('/mint', methods=['POST'])
@jwt_required()
def mint_token():
    data = request.get_json()
    cid = data.get("cid")

    if not cid:
        return jsonify({"error": "CID is required"}), 400

    try:
        file_data = upload_collection.find_one({"cid": cid})
        if not file_data:
            return jsonify({"error": "File not found in upload collection"}), 404

        serial_no = str(file_data["_id"])
        file_name = file_data["file_name"]
        user_email = get_jwt_identity()

        # ✅ Compile & Deploy Smart Contract
        abi, bytecode = compile_solidity_contract(CONTRACT_SOURCE)
        if not abi or not bytecode:
            return jsonify({"error": "Contract compilation failed. Check Solidity contract and dependencies."}), 500

        if not PRIVATE_KEY:
            return jsonify({"error": "Private key missing. Check environment variables."}), 500

        print("🚀 Deploying contract...")
        contract_address, block_number = deploy_contract(abi, bytecode)
        print(f"✅ Contract deployed at: {contract_address}, Block: {block_number}")

        # Store NFT details in MongoDB
        assets_collection.insert_one({
            "serial_no": serial_no,
            "cid": cid,
            "file_name": file_name,
            "upload_date": file_data["upload_date"],
            "owner_email": user_email,
            "block_no": block_number,
            "contract_address": contract_address
        })

        # 🗑️ Delete file from upload_collection
        delete_result = upload_collection.delete_one({"cid": cid})
        if delete_result.deleted_count > 0:
            print("✅ File deleted successfully")
        
        return jsonify({
            "message": "NFT minted successfully",
            "contract_address": contract_address,
            "block_no": block_number
        }), 201

    except Exception as e:
        print("❌ Minting Error:", str(e))
        return jsonify({"error": str(e)}), 500

    
#fetch users files for minting token
@app.route('/get_uploaded_files', methods=['GET'])
@jwt_required()
def get_uploaded_files():
    try:
        user_email = get_jwt_identity()
        if isinstance(user_email, dict):
            user_email = user_email.get("email", "")

        if not user_email:
            return jsonify({"error": "User email not found in JWT"}), 400

        user_files = list(upload_collection.find(
            {"uploaded_by_email": user_email}, 
            {"_id": 0, "file_name": 1, "cid": 1, "upload_date": 1}
        ))

        return jsonify({"files": user_files}), 200

    except Exception as e:
        print(f"❌ Error fetching uploaded files: {str(e)}")  # Essential error log
        return jsonify({"error": str(e)}), 500

    
# ✅ Update User Name
@app.route('/update_name', methods=['POST'])
def update_name():
    try:
        data = request.get_json()
        new_name = data.get("new_name")
        current_password = data.get("current_password")

        if not new_name or not current_password:
            return jsonify({"error": "All fields are required"}), 400

        # 🔹 Find user by token (Replace with actual token-based lookup)
        user = users_collection.find_one({"email": "dip@gmail.com"})  

        if not user:
            return jsonify({"error": "User not found"}), 404

        # 🔹 Verify password using bcrypt
        if not bcrypt.checkpw(current_password.encode('utf-8'), user["password"].encode('utf-8')):
            return jsonify({"error": "Incorrect password"}), 401

        # 🔹 Update the user's name in MongoDB
        users_collection.update_one({"_id": user["_id"]}, {"$set": {"full_name": new_name}})
        
        return jsonify({"message": "Name updated successfully!"}), 200

    except Exception as e:
        print(f"❌ Error updating name: {str(e)}")  # Essential error log
        return jsonify({"error": str(e)}), 500

# ✅ Change Password
@app.route('/change-password', methods=['POST'])
def change_password():
    try:
        data = request.get_json()
        email = data.get('email')
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        if not all([email, current_password, new_password, confirm_password]):
            return jsonify({"error": "All fields are required"}), 400

        # 🔹 Get user from database
        user = users_collection.find_one({"email": email})

        if not user:
            return jsonify({"error": "User not found"}), 404

        # 🔹 Verify current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), user["password"].encode('utf-8')):
            return jsonify({"error": "Current password is incorrect"}), 401

        # 🔹 Hash and update the new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        users_collection.update_one(
            {"email": email},
            {"$set": {"password": hashed_password.decode('utf-8')}}
        )

        return jsonify({"message": "Password updated successfully"}), 200

    except Exception as e:
        print(f"❌ Password change error: {str(e)}")  # Essential error log
        return jsonify({"error": str(e)}), 500

# ✅ Blockchain Status
@app.route("/api/chain-status", methods=["GET"])
def get_chain_status():
    try:
        web3 = Web3(Web3.HTTPProvider(RPC_URL))
        is_running = web3.is_connected()
        latest_block = web3.eth.block_number if is_running else None

        return jsonify({
            "isRunning": is_running,
            "latestBlock": latest_block
        }), 200
    except Exception as e:
        return jsonify({"isRunning": False, "error": str(e)}), 500

@app.route('/dashboard/files-count', methods=['GET'])
@jwt_required()
def get_files_count():
    user_email = get_jwt_identity()  # Fix applied
    count = upload_collection.count_documents({"uploaded_by_email": user_email})
    return jsonify({"files_count": count}), 200

@app.route('/dashboard/tokens-count', methods=['GET'])
@jwt_required()
def get_tokens_count():
    user_email = get_jwt_identity()  # Fix applied
    count = assets_collection.count_documents({"owner_email": user_email})
    return jsonify({"tokens_count": count}), 200

@app.route('/dashboard/deployed-blocks', methods=['GET'])
@jwt_required()
def get_deployed_blocks():
    user_email = get_jwt_identity()  # Fix applied
    blocks = assets_collection.find(
        {"owner_email": user_email},
        {"block_no": 1, "_id": 0}
    )
    block_numbers = [block["block_no"] for block in blocks]
    return jsonify({"deployed_blocks": block_numbers}), 200


# ✅ Start Flask Server
if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)