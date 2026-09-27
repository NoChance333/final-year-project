import os
import re
import json
from datetime import datetime
import requests
import bcrypt
from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from web3 import Web3
from eth_account import Account
import solcx

# Load environment variables
load_dotenv()

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "backend", "templates"),
    static_folder=os.path.join(BASE_DIR, "backend", "static")
)

# Enable CORS
CORS(app, supports_credentials=True, allow_headers=["Content-Type", "Authorization"])

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'novis_bca_super_secret_jwt_key_2026')
jwt = JWTManager(app)

# Blockchain & IPFS Configuration
PINATA_JWT = os.getenv('PINATA_JWT')
PINATA_API_KEY = os.getenv('PINATA_API_KEY')
PINATA_SECRET_KEY = os.getenv('PINATA_SECRET_KEY')
IPFS_API_URL = os.getenv('IPFS_API_URL', 'http://127.0.0.1:5001/api/v0/add')
RPC_URL = os.getenv('RPC_URL', 'http://127.0.0.1:8545')
CHAIN_ID = int(os.getenv('CHAIN_ID', '12345'))
PRIVATE_KEY = os.getenv('PRIVATE_KEY', '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80')
CONTRACT_ADDRESS_ENV = os.getenv('CONTRACT_ADDRESS')
SOLC_PATH = os.getenv('SOLC_PATH', r'C:\Users\ASUS\.solcx\solc-v0.8.20\solc.exe')
CONTRACT_FILE = os.path.join(BASE_DIR, "blockchain", "contracts", "CIDToken.sol")
DEPLOYED_RECEIPT_FILE = os.path.join(BASE_DIR, "backend", "deployed_contract.json")

# Database Configuration (Robust MongoDB with in-memory fallback)
mongo_uri = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/tokenized_asset")
client = None
db = None
users_collection = None
upload_collection = None
assets_collection = None

def init_db():
    global client, db, users_collection, upload_collection, assets_collection
    try:
        from pymongo import MongoClient
        test_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=2000)
        test_client.admin.command('ping')
        client = test_client
        db = client["tokenized_asset"]
        print("[INFO] MongoDB connected successfully to server")
    except Exception as e:
        print(f"[WARN] Primary MongoDB server not accessible ({e}). Initializing in-memory fallback database.")
        import mongomock
        client = mongomock.MongoClient()
        db = client["tokenized_asset"]

    users_collection = db["users"]
    upload_collection = db["upload"]
    assets_collection = db["assets"]

init_db()

def ensure_db_ready():
    if users_collection is None or upload_collection is None or assets_collection is None:
        init_db()

# Smart Contract Management
_cached_abi = None
_cached_bytecode = None
_cached_contract_address = None

def compile_cid_contract():
    global _cached_abi, _cached_bytecode
    if _cached_abi and _cached_bytecode:
        return _cached_abi, _cached_bytecode

    precompiled_file = os.path.join(BASE_DIR, "blockchain", "contracts", "CIDToken.json")
    if os.path.exists(precompiled_file):
        try:
            with open(precompiled_file, "r") as f:
                data = json.load(f)
                _cached_abi = data.get("abi")
                _cached_bytecode = data.get("bin")
                if _cached_abi and _cached_bytecode:
                    return _cached_abi, _cached_bytecode
        except Exception as e:
            print("[WARN] Error loading precompiled CIDToken.json:", e)

    if not os.path.exists(SOLC_PATH):
        solcx.install_solc("0.8.20")

    blockchain_dir = os.path.join(BASE_DIR, "blockchain")
    compiled = solcx.compile_files(
        [CONTRACT_FILE],
        output_values=['abi', 'bin'],
        base_path=blockchain_dir,
        allow_paths=[blockchain_dir],
        solc_binary=SOLC_PATH
    )

    contract_key = [k for k in compiled.keys() if k.endswith(":CIDToken")][0]
    _cached_abi = compiled[contract_key]['abi']
    _cached_bytecode = compiled[contract_key]['bin']
    return _cached_abi, _cached_bytecode

def get_or_deploy_contract(web3):
    global _cached_contract_address
    abi, bytecode = compile_cid_contract()

    # 1. Check environment variable first (e.g. pre-deployed contract on Sepolia)
    if CONTRACT_ADDRESS_ENV and Web3.is_address(CONTRACT_ADDRESS_ENV):
        _cached_contract_address = Web3.to_checksum_address(CONTRACT_ADDRESS_ENV)
        return _cached_contract_address, abi

    # 2. Check if we already have a valid deployed contract address cached in memory
    if _cached_contract_address:
        code = web3.eth.get_code(_cached_contract_address)
        if code and code != b'' and code != b'\x00':
            return _cached_contract_address, abi

    # 3. Check receipt file
    if os.path.exists(DEPLOYED_RECEIPT_FILE):
        try:
            with open(DEPLOYED_RECEIPT_FILE, "r") as f:
                data = json.load(f)
                cand = data.get("contract_address")
                receipt_chain = data.get("chain_id")
                # Only reuse if chain matches current web3 chain
                if cand and (receipt_chain is None or receipt_chain == web3.eth.chain_id):
                    cand_cs = Web3.to_checksum_address(cand)
                    code = web3.eth.get_code(cand_cs)
                    if code and code != b'' and code != b'\x00':
                        _cached_contract_address = cand_cs
                        return _cached_contract_address, abi
        except Exception as e:
            print("[WARN] Reading deployed contract receipt error:", e)

    # 4. Deploy new contract using deployer account
    account = Account.from_key(PRIVATE_KEY)
    print(f"[INFO] Deploying CIDToken contract with deployer {account.address} on Chain ID {web3.eth.chain_id}...")
    contract_factory = web3.eth.contract(abi=abi, bytecode=bytecode)
    nonce = web3.eth.get_transaction_count(account.address)

    latest_block = web3.eth.get_block('latest')
    base_fee = latest_block.get('baseFeePerGas', 1000000000)
    try:
        max_priority_fee = web3.eth.max_priority_fee
    except Exception:
        max_priority_fee = web3.to_wei(2, 'gwei')
    max_fee = int(base_fee * 1.5) + max_priority_fee

    tx = contract_factory.constructor().build_transaction({
        'chainId': web3.eth.chain_id,
        'from': account.address,
        'nonce': nonce,
        'gas': 3000000,
        'maxFeePerGas': max_fee,
        'maxPriorityFeePerGas': max_priority_fee,
    })

    signed = account.sign_transaction(tx)
    tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    _cached_contract_address = receipt.contractAddress
    print(f"[SUCCESS] CIDToken deployed at: {_cached_contract_address} (Block {receipt.blockNumber})")

    try:
        with open(DEPLOYED_RECEIPT_FILE, "w") as f:
            json.dump({
                "contract_address": _cached_contract_address,
                "block_number": receipt.blockNumber,
                "deployer": account.address,
                "tx_hash": tx_hash.hex()
            }, f, indent=2)
    except Exception as e:
        print("[WARN] Could not write deployed_contract.json:", e)

    return _cached_contract_address, abi

# Frontend Page Routes
@app.route("/")
def home_page():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

# User Registration & Authentication
@app.route('/register', methods=['POST'])
def register():
    ensure_db_ready()
    data = request.get_json() or {}
    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')

    if not full_name or not email or not password:
        return jsonify({"error": "Full Name, Email, and Password are required"}), 400

    email_pattern = r"^[a-zA-Z0-9._%+-]+@gmail\.com$"
    if not re.match(email_pattern, email):
        return jsonify({"error": "Only Gmail addresses are allowed"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"error": "Email already exists"}), 400

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users_collection.insert_one({
        "full_name": full_name,
        "email": email,
        "password": hashed_password
    })

    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    try:
        ensure_db_ready()
        data = request.get_json() or {}
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        user = users_collection.find_one({"email": email})
        if not user or not bcrypt.checkpw(password.encode(), user["password"].encode()):
            return jsonify({"error": "Invalid credentials"}), 401

        access_token = create_access_token(identity=email)

        return jsonify({
            "message": "Login successful",
            "access_token": access_token,
            "user": {"email": email, "full_name": user.get("full_name", "User")}
        }), 200

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# File Upload to IPFS
@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    try:
        ensure_db_ready()
        user_info = get_jwt_identity()
        user_email = user_info.get('email') if isinstance(user_info, dict) else user_info

        user = users_collection.find_one({"email": user_email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        filename = secure_filename(file.filename)
        file_bytes = file.read()
        ipfs_hash = None

        # Upload file to IPFS (Pinata Cloud if credentials provided, else local IPFS daemon)
        if PINATA_JWT or (PINATA_API_KEY and PINATA_SECRET_KEY):
            headers = {}
            if PINATA_JWT:
                headers['Authorization'] = f"Bearer {PINATA_JWT.strip()}"
            else:
                headers['pinata_api_key'] = PINATA_API_KEY.strip()
                headers['pinata_secret_api_key'] = PINATA_SECRET_KEY.strip()

            pinata_files = {'file': (filename, file_bytes, file.mimetype or 'application/octet-stream')}
            try:
                res = requests.post(
                    "https://api.pinata.cloud/pinning/pinFileToIPFS",
                    files=pinata_files,
                    headers=headers,
                    timeout=30
                )
                if res.status_code == 200:
                    pinata_data = res.json()
                    ipfs_hash = pinata_data.get("IpfsHash") or pinata_data.get("Hash")
                    print(f"[SUCCESS] Uploaded to Pinata IPFS: CID={ipfs_hash}")
                else:
                    print(f"[WARN] Pinata upload error: {res.status_code} - {res.text}")
                    return jsonify({"error": "Pinata IPFS upload failed", "details": res.text}), 500
            except Exception as e:
                print(f"[ERROR] Pinata connection failed: {e}")
                return jsonify({"error": f"Failed to connect to Pinata IPFS: {str(e)}"}), 500
        else:
            # Fallback to local IPFS daemon
            files_payload = {'file': (filename, file_bytes, file.mimetype or 'application/octet-stream')}
            try:
                ipfs_response = requests.post(IPFS_API_URL, files=files_payload, timeout=30)
                if ipfs_response.status_code != 200:
                    return jsonify({"error": "Local IPFS upload failed", "details": ipfs_response.text}), 500
                ipfs_data = ipfs_response.json()
                ipfs_hash = ipfs_data.get("Hash")
                print(f"[SUCCESS] Uploaded to Local IPFS: CID={ipfs_hash}")
            except Exception as e:
                return jsonify({"error": f"Failed to connect to IPFS: {str(e)}. (Set PINATA_JWT or PINATA_API_KEY/SECRET for cloud hosting)"}), 500

        # Store metadata in MongoDB upload collection
        upload_data = {
            "cid": ipfs_hash,
            "file_name": filename,
            "description": request.form.get('description', ''),
            "upload_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "uploaded_by_email": user_email,
            "uploaded_by_username": user.get("full_name", user.get("username", "Unknown"))
        }

        upload_collection.insert_one(upload_data)

        return jsonify({
            "message": "File uploaded successfully to IPFS",
            "cid": ipfs_hash,
            "file_name": filename
        }), 201

    except Exception as e:
        print(f"[ERROR] Upload Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Fetch Uploaded Files for Minting
@app.route('/get_uploaded_files', methods=['GET'])
@jwt_required()
def get_uploaded_files():
    try:
        ensure_db_ready()
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
        print(f"[ERROR] Error fetching uploaded files: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Mint ERC-721 Token (With direct transfer to user MetaMask wallet)
@app.route('/mint', methods=['POST'])
@jwt_required()
def mint_token():
    ensure_db_ready()
    data = request.get_json() or {}
    cid = data.get("cid")
    wallet_address = data.get("wallet_address") or data.get("recipient_wallet")

    if not cid:
        return jsonify({"error": "CID is required"}), 400

    try:
        file_data = upload_collection.find_one({"cid": cid})
        if not file_data:
            return jsonify({"error": "File not found in upload collection"}), 404

        serial_no = str(file_data.get("_id", ""))
        file_name = file_data["file_name"]
        user_email = get_jwt_identity()

        # Connect to Ethereum execution client
        web3 = Web3(Web3.HTTPProvider(RPC_URL))
        if not web3.is_connected():
            return jsonify({"error": "Failed to connect to Ethereum Node (Geth). Ensure devnet is running."}), 500

        account = Account.from_key(PRIVATE_KEY)

        # Determine token recipient (MetaMask wallet if connected, otherwise deployer)
        if wallet_address and Web3.is_address(wallet_address):
            recipient = Web3.to_checksum_address(wallet_address)
        else:
            # Fallback to deployer address
            recipient = account.address

        contract_address, abi = get_or_deploy_contract(web3)
        contract = web3.eth.contract(address=contract_address, abi=abi)

        # Build EIP-1559 mint transaction
        nonce = web3.eth.get_transaction_count(account.address)
        latest_block = web3.eth.get_block('latest')
        base_fee = latest_block.get('baseFeePerGas', 1000000000)
        try:
            max_priority_fee = web3.eth.max_priority_fee
        except Exception:
            max_priority_fee = web3.to_wei(2, 'gwei')
        max_fee = int(base_fee * 1.5) + max_priority_fee

        mint_tx = contract.functions.mintToken(recipient, cid).build_transaction({
            'chainId': web3.eth.chain_id,
            'from': account.address,
            'nonce': nonce,
            'gas': 600000,
            'maxFeePerGas': max_fee,
            'maxPriorityFeePerGas': max_priority_fee,
        })

        signed_mint = account.sign_transaction(mint_tx)
        tx_hash = web3.eth.send_raw_transaction(signed_mint.raw_transaction)
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

        # Determine minted token ID
        token_id = None
        try:
            token_id = contract.functions.totalMinted().call()
        except Exception:
            token_id = 1

        # Store NFT details in MongoDB assets collection
        assets_collection.insert_one({
            "serial_no": serial_no,
            "cid": cid,
            "file_name": file_name,
            "upload_date": file_data.get("upload_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "owner_email": user_email,
            "recipient_wallet": recipient,
            "token_id": token_id,
            "block_no": receipt.blockNumber,
            "contract_address": contract_address,
            "tx_hash": tx_hash.hex()
        })

        # Remove from upload collection
        upload_collection.delete_one({"cid": cid})

        return jsonify({
            "message": "NFT minted successfully and transferred to wallet!",
            "contract_address": contract_address,
            "token_id": token_id,
            "block_no": receipt.blockNumber,
            "tx_hash": tx_hash.hex(),
            "recipient": recipient
        }), 201

    except Exception as e:
        print(f"[ERROR] Minting Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Blockchain & Transactions Status API
@app.route("/api/chain-status", methods=["GET"])
def get_chain_status():
    try:
        web3 = Web3(Web3.HTTPProvider(RPC_URL))
        is_running = web3.is_connected()
        latest_block = web3.eth.block_number if is_running else None
        chain_id = web3.eth.chain_id if is_running else None

        chain_name = "Sepolia Testnet" if chain_id == 11155111 else ("Polygon Amoy" if chain_id == 80002 else f"Local Devnet ({chain_id})")

        return jsonify({
            "isRunning": is_running,
            "latestBlock": latest_block,
            "chainId": chain_id,
            "chainName": chain_name,
            "contractAddress": _cached_contract_address,
            "rpcUrl": RPC_URL
        }), 200
    except Exception as e:
        return jsonify({"isRunning": False, "error": str(e)}), 200

@app.route("/api/recent-transactions", methods=["GET"])
def get_recent_transactions():
    try:
        ensure_db_ready()
        recent = list(assets_collection.find({}, {"_id": 0}).sort("block_no", -1).limit(10))
        return jsonify({"transactions": recent}), 200
    except Exception as e:
        return jsonify({"transactions": [], "error": str(e)}), 200

# Dashboard Statistics
@app.route('/dashboard/files-count', methods=['GET'])
@jwt_required()
def get_files_count():
    ensure_db_ready()
    user_email = get_jwt_identity()
    count = upload_collection.count_documents({"uploaded_by_email": user_email})
    return jsonify({"files_count": count}), 200

@app.route('/dashboard/tokens-count', methods=['GET'])
@jwt_required()
def get_tokens_count():
    ensure_db_ready()
    user_email = get_jwt_identity()
    count = assets_collection.count_documents({"owner_email": user_email})
    return jsonify({"tokens_count": count}), 200

@app.route('/dashboard/deployed-blocks', methods=['GET'])
@jwt_required()
def get_deployed_blocks():
    ensure_db_ready()
    user_email = get_jwt_identity()
    blocks = assets_collection.find(
        {"owner_email": user_email},
        {"block_no": 1, "_id": 0}
    )
    block_numbers = [block["block_no"] for block in blocks if "block_no" in block]
    return jsonify({"deployed_blocks": block_numbers}), 200

# User Profile Management
@app.route('/update_name', methods=['POST'])
def update_name():
    try:
        ensure_db_ready()
        data = request.get_json() or {}
        email = data.get("email")
        new_name = data.get("new_name")
        current_password = data.get("current_password")

        if not email or not new_name or not current_password:
            return jsonify({"error": "All fields are required"}), 400

        user = users_collection.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        if not bcrypt.checkpw(current_password.encode('utf-8'), user["password"].encode('utf-8')):
            return jsonify({"error": "Incorrect password"}), 401

        users_collection.update_one({"_id": user["_id"]}, {"$set": {"full_name": new_name}})
        return jsonify({"message": "Name updated successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/change-password', methods=['POST'])
def change_password():
    try:
        ensure_db_ready()
        data = request.get_json() or {}
        email = data.get('email')
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        if not all([email, current_password, new_password, confirm_password]):
            return jsonify({"error": "All fields are required"}), 400

        if new_password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400

        user = users_collection.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        if not bcrypt.checkpw(current_password.encode('utf-8'), user["password"].encode('utf-8')):
            return jsonify({"error": "Current password is incorrect"}), 401

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        users_collection.update_one(
            {"email": email},
            {"$set": {"password": hashed_password}}
        )

        return jsonify({"message": "Password updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)