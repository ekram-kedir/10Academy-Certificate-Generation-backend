import base64
import os
import sys
from typing import Self
sys.path.append(os.path.abspath(os.path.join('../scripts')))
from kmd_wallet import KmdAlgorand
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from enum import Enum
from flask_bcrypt import Bcrypt
from algosdk import account, mnemonic, transaction
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, jwt_required
from algosdk.v2client import algod

from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from enum import Enum
from flask_bcrypt import Bcrypt
from algosdk import account, mnemonic, transaction
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, jwt_required
from algosdk.v2client import algod
import uuid
from algosdk import mnemonic

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_strong_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://ekru:ekram12345@localhost/nft_system'
jwt = JWTManager(app)  # Initialize JWTManager
db = SQLAlchemy(app)
CORS(app)
# Specify the node address and token.
algod_address = "http://localhost:4001"
algod_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
algod_client = algod.AlgodClient(algod_token=algod_token, algod_address=algod_address)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'Issuer' or 'Trainee'
    wallet_address = db.Column(db.String(255), nullable=False)
    wallet_mnemonic = db.Column(db.String(255), nullable=False)
class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    nft_asset_id = db.Column(db.Integer, nullable=False)  # Algorand NFT asset ID
    issuer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # ID of the issuer
    issued_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    ipfs_hash = db.Column(db.String(255), nullable=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey('certificate.id'), nullable=False)

      # IPFS hash of certificate data (optional)
class OptInRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trainee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    certificate_id = db.Column(db.Integer, db.ForeignKey('certificate.id'), nullable=False)
    public_key = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Enum('pending', 'approved', 'denied', name='optin_status'), default='pending')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


# Create tables
with app.app_context():
    db.create_all()
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    role = request.json.get('role')  # 'Issuer' or 'Trainee'
    # Check for existing user
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"message": "Username already exists"}), 400
    # Create Algorand wallet
    private_key, address = account.generate_account()
    mnemonic_phrase = mnemonic.from_private_key(private_key)
    hashed_password = Bcrypt().generate_password_hash(password).decode('utf-8')
    # Create user object
    user = User(
        username=username,
        password_hash=hashed_password,
        role=role,
        wallet_address=address,
        wallet_mnemonic=mnemonic_phrase,
    )
    # Add user to database
    db.session.add(user)
    db.session.commit()
    # Return success message (optionally with wallet information)
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    # Find user by username
    user = User.query.filter_by(username=username).first()
    if user and Bcrypt().check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=user.id)  # Generate access token
        return jsonify({"access_token": access_token}), 200
    else:
        return jsonify({"message": "Invalid username or password"}), 401


from flask import request, jsonify

from flask_jwt_extended import jwt_required, get_jwt_identity

# ... other imports

from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
import algosdk  # Assuming you're using the algosdk library
# ... other necessary imports (e.g., for database models)

# ... your Flask app setup and configuration

@app.route('/asset_creation', methods=['POST'])
@jwt_required()
def create_asset_for_staff():
    current_user_id = get_jwt_identity()
    current_user = User.query.filter_by(id=current_user_id).first()  # Assuming you have a User model

    if current_user.role != 'staff':
        return jsonify({'error': 'Unauthorized to create assets'}), 401

    data = request.json

    # Extract necessary asset details from request data
    asset_name = data.get('asset_name')
    unit_name = data.get('unit_name')
    total = data.get('total')
    url = data.get('url')

    # Validate asset details (e.g., check for required fields, valid values)
    # ...

    try:
        # Retrieve sender address and private key securely
        sender_address = current_user.wallet_address
        sender_mnemonic = current_user.wallet_mnemonic
        sender_private_key = mnemonic.to_private_key(sender_mnemonic)
        # sender_private_key = base64.b64encode(sender_private_key.encode()).decode()
  # Assuming secret_key is in Base64 format

        # Create the asset transaction
        sp = algod_client.suggested_params()
        txn = transaction.AssetConfigTxn(
            sender=sender_address,
            sp=sp,
            default_frozen=False,
            unit_name=unit_name,
            asset_name=asset_name,
            manager=sender_address,
            reserve=sender_address,
            freeze=sender_address,
            clawback=sender_address,
            url=url,
            total=total,
            decimals=0,
            certificate_id=current_user_id
        )

        # Sign and send the transaction
        stxn = txn.sign(sender_private_key)
        txid = algod_client.send_transaction(stxn)
        results = transaction.wait_for_confirmation(algod_client, txid, 4)

        return jsonify({'message': 'Asset created successfully', 'results': results}), 201

    except Exception as e:
        print(f"Error creating asset: {e}")
        return jsonify({'error': 'Failed to create asset'}), 500

@app.route('/opt-in-requests', methods=['POST'])
@jwt_required()
def create_opt_in_request():
    current_user_id = get_jwt_identity()
    current_user = User.query.filter_by(id=current_user_id).first()

    if current_user.role != 'trainee':
        return jsonify({'error': 'Unauthorized to create opt-in requests '}, f"{current_user.role}"), 401

    # Create opt-in request using the determined certificate_id
    opt_in_request = OptInRequest(
        trainee_id=current_user_id, 
        public_key=current_user.wallet_address,
        certificate_id=current_user_id
                                                                                                                                                                                                                        )
    db.session.add(opt_in_request)
    db.session.commit()
 
    # After creating the OptInRequest object in the database:

    # try:
    sp = algod_client.suggested_params()
    optin_txn = transaction.AssetOptInTxn(
        sender=current_user.wallet_address,  # Use the trainee's address
        sp=sp,
        index=current_user_id

    )
    sender_mnemonic = current_user.wallet_mnemonic
    sender_private_key = mnemonic.to_private_key(sender_mnemonic)
    signed_optin_txn = optin_txn.sign(sender_private_key)  # Retrieve private key securely
    txid = algod_client.send_transaction(signed_optin_txn)
    results = transaction.wait_for_confirmation(algod_client, txid, 4)

    # Return additional information about the opt-in transaction
    return jsonify({
        'message': 'Opt-in request submitted and transaction completed',
        'txid': txid,
        'results': results
    }), 201

    # except Exception as e:
    #     print(f"Error during opt-in transaction: {e}")
    #     return jsonify({'error': 'Failed to complete opt-in transaction'}), 500















# @app.route('/asset_optin', methods=['POST'])
# @jwt_required()
# def opt_in_to_asset():
#     current_user_id = get_jwt_identity()
#     current_user = User.query.filter_by(id=current_user_id).first()

#     if current_user.role != 'trainee':
#         return jsonify({'error': 'Unauthorized to opt in to assets'}), 401

#     data = request.json
#     public_key = data.get('public_key')

#     try:
#         asset_id = asset_id_mapping.get(public_key)

#         if asset_id:
#             # Existing asset found, proceed with opt-in
#             sender_address = current_user.wallet_address
#             sp = algod_client.suggested_params()
#             txn = transaction.AssetTransferTxn(
#                 sender=sender_address,
#                 sp=sp,
#                 receiver=sender_address,
#                 amt=0,
#                 index=asset_id
#             )
#             sender_private_key = current_user.secret_key  # Assuming secret_key is in Base64 format
#             stxn = txn.sign(sender_private_key)
#             txid = algod_client.send_transaction(stxn)
#             results = transaction.wait_for_confirmation(algod_client, txid, 4)
#             return jsonify({'message': 'Asset opt-in successful', 'results': results}), 200
#         else:
#             # Asset not found, create pending opt-in request
#             pending_optin = PendingOptin(
#                 public_key=public_key,
#                 user_id=current_user_id,
#                 timestamp=int(time.time())  # Store current timestamp
#             )
#             db.session.add(pending_optin)
#             db.session.commit()
#             return jsonify({'message': 'Pending asset opt-in request created'}), 202

#     except Exception as e:
#         print(f"Error opting in to asset: {e}")
#         return jsonify({'error': 'Failed to opt in to asset'}), 500


# @app.route('/transfer_asset', methods=['POST'])
# @jwt_required()
# def transfer_asset():
#     data = request.get_json()
#     asset_id = data.get("asset_id")
#     recipient_address = data.get("recipient_address")
#     amount = data.get("amount")

#     try:
#         sp = algod_client.suggested_params()
#         txn = transaction.AssetTransferTxn(
#             sender=current_user.address,
#             sp=sp,
#             receiver=recipient_address,
#             amt=amount,
#             index=asset_id,
#         )
#         stxn = txn.sign(current_user.private_key)
#         txid = algod_client.send_transaction(stxn)
#         results = transaction.wait_for_confirmation(algod_client, txid, 4)
#         return jsonify({"transaction_id": txid}), 200
#     except Exception as e:
#         return jsonify({"error": str(e)}), 400





# @app.route('/submit_optin_request', methods=['POST'])
# @jwt_required()
# def submit_optin_request():
#     user_id = get_jwt_identity()
#     current_user = User.query.filter_by(id=user_id).first()

#     # Authorization check (only trainees can submit requests)
#     if current_user.role != 'trainee':
#         return jsonify({"message": "Unauthorized"}), 401

#     certificate_id = request.json.get('certificate_id')
#     public_key = request.json.get('public_key')

#     # Validate inputs (e.g., check if certificate exists, validate public key format)
#     # ...

#     optin_request = OptInRequest(
#         trainee_id=current_user.id,
#         certificate_id=certificate_id,
#         public_key=public_key
#     )
#     db.session.add(optin_request)
#     db.session.commit()

#     return jsonify({"message": "Opt-in request submitted successfully"}), 201

# @app.route('/pending_optin_requests', methods=['GET'])
# @jwt_required()

# def get_pending_optin_requests():
#     user_id = get_jwt_identity()
#     current_user = User.query.filter_by(id=user_id).first()

#     # Authorization check (only staff can view pending requests)
#     if current_user.role != 'staff':
#         return jsonify({"message": "Unauthorized"}), 401

#     pending_requests = OptInRequest.query.filter_by(status='pending').all()
#     return jsonify([request.to_dict() for request in pending_requests]), 200


# @app.route('/approve_optin_request/<request_id>', methods=['POST'])
# @jwt_required()
# def approve_optin_request(request_id):
#     user_id = get_jwt_identity()
#     current_user = User.query.filter_by(id=user_id).first()

#     # Authorization check (only staff can approve/deny requests)
#     if current_user.role != 'staff':
#         return jsonify({"message": "Unauthorized"}), 401

#     optin_request = OptInRequest.query.filter_by(id=request_id).first()
#     if not optin_request:
#         return jsonify({"message": "Invalid request ID"}), 404

#     # Transfer NFT to trainee's public key
#     # ... (Use Algorand SDK to transfer the NFT asset)

#     optin_request.status = 'approved'
#     db.session.commit()

#     return jsonify({"message": "Request approved successfully"}), 200

# # Similarly, create a route for denying requests (e.g., /deny_optin_request/<request_id>)
# from algosdk import transaction


# from flask import jsonify
# from flask_jwt_extended import jwt_required, get_jwt_identity

# def charge_balance():
#     try:
#         current_user_id = get_jwt_identity()
#         current_user = User.query.filter_by(id=current_user_id).first()
#         balance = kmd_algo.query_account_information(current_user)["amount"]
#         # Assuming you have a balance field in your User model
#         if balance >= 1010:
#             return jsonify({"message": "Sufficient balance!"}), 200

#         charge_result = charge_balance_transaction(current_user)
#         if charge_result == "Balance charged successfully!":
#             return jsonify({"message": "Balance charged, please proceed!"}), 200
#         else:
#             return jsonify({"message": charge_result}), 400

#     except Exception as e:
#         return jsonify({"message": f"Error charging balance: {str(e)}"}), 500

# def charge_balance_transaction(user):
#     current_user_id = get_jwt_identity()
#     current_user = User.query.filter_by(id=current_user_id).first()
#     algod_client = Self.set_up_algod_client()
#     account_info = algod_client.account_info(user.wallet_address) 

#     balance = account_info["amount"]
#     print(balance)
#     try:
#         kmd_algo = KmdAlgorand()  # Initialize KMD client

#         # Retrieve source account details from the default user wallet
#         default_wallet = kmd_algo.create_user_wallet(
#             wallet_name="unencrypted-default-wallet",
#             wallet_password=""  # Provide password if needed
#         )
#         default_account = kmd_algo.list_keys(default_wallet)[0]  # Assuming single account in default wallet

#         # Send Algos from the default account to the user's account
#         send_alogs_transaction(
#             algod_client=kmd_algo.set_up_algod_client(),
#             receiver_address=user.wallet_address,
#             sender_address=default_account,
#             sender_private_key=kmd_algo.export_key(default_account, wallet_password=""),
#             amount=1000
#         )

#         # Update user's balance in the database
#         balance += 1000
#         db.session.commit()

#         # Provide success feedback to the user
#         return "Balance charged successfully!"

#     except Exception as e:
#         # Handle other errors
#         return f"Error charging balance: {e}"

# def send_alogs_transaction(algod_client, receiver_address, sender_address, sender_private_key, amount):
#     try:
#         # Construct the transaction
#         params = algod_client.suggested_params()

#         txn = transaction.PaymentTxn(
#             algod_client=algod_client,
#             sender=sender_address,
#             receiver=receiver_address,
#             amt=amount,
#             sp=sender_private_key
#         )

#         # Sign the transaction with the sender's private key
#         signed_txn = txn.sign(sender_private_key)

#         # Send the transaction to the Algorand network
#         tx_id = algod_client.send_transaction(signed_txn)
#         print("Transaction ID:", tx_id)

#         # You may want to return a success message or an empty response here
#         return jsonify({"message": "Transaction successful"}), 200

#     except Exception as e:
#         print("Transaction failed:", e)
#         # You may want to return an error response here
#         return jsonify({"message": f"Transaction failed: {str(e)}"}), 500
# from flask import jsonify
# from algosdk import transaction
# from algosdk.v2client import algod


# @app.route('/charge_balance', methods=['POST'])
# @jwt_required()

# def send_alogs_transaction(algod_client, receiver_address, sender_address, sender_private_key, amount):

#     # Construct the transaction
#     params = algod_client.suggested_params()

#     txn = transaction.PaymentTxn(
#         sender=sender_address,
#         receiver=receiver_address,
#         amt=amount,
#         sp=params
#     )

#     # Sign the transaction with the sender's private key
#     signed_txn = txn.sign(sender_private_key)

#     # Send the transaction to the Algorand network
#     try:
#         tx_id = algod_client.send_transaction(signed_txn)
#         print("Transaction ID:", tx_id)
#     except Exception as e:
#         print("Transaction failed:", e)
        
# def charge_balance():
#    kmd_algo = KmdAlgorand()
#    DEFAULT_KMD_WALLET_NAME = "unencrypted-default-wallet"
#    DEFAULT_KMD_WALLET_PASSWORD = ""
#    default_wallet = kmd_algo.create_user_wallet(wallet_name=DEFAULT_KMD_WALLET_NAME, wallet_password=DEFAULT_KMD_WALLET_PASSWORD)
#    current_user_id = get_jwt_identity()
#    current_user = User.query.filter_by(id=current_user_id).first()
#    print(current_user)
#    user_wallet = current_user["address"]

#    default_account = default_wallet.list_keys()[0]
#    user_account = user_wallet.list_keys()[0]
#    algod_address = "http://localhost:4001"
#    algod_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# # Initialize an algod client
#    algod_client = algod.AlgodClient(algod_token=algod_token, algod_address=algod_address) 
#    sender_private_key = default_wallet.export_key(default_account)
#    send_alogs_transaction(
#         algod_client=algod_client, 
#         receiver_address=user_account, 
#         sender_address=default_account, 
#         sender_private_key=sender_private_key, 
#         amount=1000000)

   
import logging
from flask import jsonify

# ... (other imports)

@app.route('/charge_balance', methods=['POST'])
@jwt_required()
def charge_balance():
    logging.info("Starting charge_balance transaction")

    try:
        kmd_algo = KmdAlgorand()
        DEFAULT_KMD_WALLET_NAME = "unencrypted-default-wallet"
        DEFAULT_KMD_WALLET_PASSWORD = ""
        default_wallet = kmd_algo.create_user_wallet(
            wallet_name=DEFAULT_KMD_WALLET_NAME, wallet_password=DEFAULT_KMD_WALLET_PASSWORD
        )
        current_user_id = get_jwt_identity()
        current_user = User.query.filter_by(id=current_user_id).first()
        user_wallet_address = current_user.wallet_address  # Assuming address is stored

        default_account = default_wallet.list_keys()[0]
        user_account = user_wallet_address  # Assuming the address itself is the account
        algod_address = "http://localhost:4001"
        algod_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        algod_client = algod.AlgodClient(algod_token=algod_token, algod_address=algod_address)
        sender_private_key = default_wallet.export_key(default_account)

        transaction_id = send_alogs_transaction(
            algod_client=algod_client,
            receiver_address=user_account,
            sender_address=default_account,
            sender_private_key=sender_private_key,
            amount=500
        )

        logging.info("Transaction successful: %s", transaction_id)
        return jsonify({"message": "Transaction successful", "transaction_id": transaction_id}), 200

    except Exception as e:
        logging.error("Transaction failed: %s", e)
        return jsonify({"message": "Transaction failed", "error": str(e)}), 500

def send_alogs_transaction(algod_client, receiver_address, sender_address, sender_private_key, amount):
    logging.info("Constructing transaction...")

    params = algod_client.suggested_params()
    txn = transaction.PaymentTxn(
        sender=sender_address, receiver=receiver_address, amt=amount, sp=params
    )
    signed_txn = txn.sign(sender_private_key)

    logging.info("Sending transaction to Algorand network...")
    tx_id = algod_client.send_transaction(signed_txn)
    return tx_id



# @app.route('/issue_certificate/<trainee_id>', methods=['POST'])
# # @jwt_required()
# def issue_certificate(trainee_id):
#     user_id = get_jwt_identity()  # Get current user from JWT
#     current_user = User.query.filter_by(id=user_id).first()
#     print(f"current_user: {current_user.role}")
#     # Authorization check
#     if current_user.role != 'staff':
#         return jsonify({"message": "Unauthorized"}), 401
#     # ... (Code for generating certificate data and storing on IPFS)
#     ipfs_hash = "https://ibb.co/PFCbvS3"  # IPFS hash of certificate data
#     # Create Algorand NFT
#     params = algod_client.suggested_params()
#     params.flat_fee = 0  # Set flat fee to 1000 microAlgos
#     params.fee=0
#     txn = transaction.AssetConfigTxn(
#         sender=account.address_from_private_key(mnemonic.to_private_key(current_user.wallet_mnemonic)),  # Use issuer's mnemonic
#         sp=params,
#         total=1,
#         default_frozen=False,
#         asset_name="Certificate",
#         unit_name="Cert",
#         url=ipfs_hash,
#         decimals=0,
#         manager=account.address_from_private_key(mnemonic.to_private_key(current_user.wallet_mnemonic)),  # Or any appropriate address
#         freeze=account.address_from_private_key(mnemonic.to_private_key(current_user.wallet_mnemonic)),  # Or any appropriate address
#         reserve=account.address_from_private_key(mnemonic.to_private_key(current_user.wallet_mnemonic)),  # Or any appropriate address
#         clawback=account.address_from_private_key(mnemonic.to_private_key(current_user.wallet_mnemonic)),  # Or any appropriate address
#     )
#     signed_txn = txn.sign(mnemonic.to_private_key(current_user.wallet_mnemonic))
#     tx_id = algod_client.send_transaction(signed_txn)
#     nft_asset_id = signed_txn.get_asset_index()
#     # Create Certificate object in database
#     certificate = Certificate(
#         user_id=trainee_id,
#         nft_asset_id=nft_asset_id,
#         issuer_id=current_user.id,
#         title="Certificate of Completion",  # Example title
#         description="Congratulations on completing the course!",  # Example description
#         ipfs_hash=ipfs_hash
#     )
#     db.session.add(certificate)
#     db.session.commit()
#     return jsonify({"message": "NFT certificate issued successfully"}), 201

if __name__ == '__main__':
    app.run()