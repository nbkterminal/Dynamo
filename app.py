# app.py
# This is the main Flask application for the BlackRock Payment Terminal.
# It handles user authentication, transaction flow, direct communication with an external
# ISO 8583 server for card authorization via TCP sockets, and real-time cryptocurrency payouts.

import os
import json
import hashlib
import logging
import random
import re
from datetime import datetime, date, timedelta
from functools import wraps
import socket # For direct TCP socket communication with ISO 8583 server
import struct # For packing/unpacking binary data (e.g., message length)

from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# Firebase Admin SDK for server-side interaction with Firestore
import firebase_admin
from firebase_admin import credentials, firestore, auth # Added for Firebase initialization

# Import custom modules for blockchain interaction and utilities
from blockchain_client import BlockchainClient # Handles crypto payouts
from utils import validate_card_number, format_amount, generate_transaction_id # Keeping utils for card validation, etc.
from security_middleware import SecurityMiddleware, audit_log, require_role
from production_config import get_production_config, validate_production_config # For production readiness checks
from application_config import get_wallet_config # For merchant wallet addresses

# Configure logging for the application
logging.basicConfig(level=logging.INFO) # Set to INFO for production, DEBUG for development
logger = logging.getLogger(__name__)

app = Flask(__name__)
# IMPORTANT: In a real production environment, app.secret_key MUST be a long,
# randomly generated string stored securely (e.g., in an environment variable).
# The default here is for development/demonstration purposes only.
app.secret_key = os.environ.get("SESSION_SECRET", "blackrock_terminal_secret_2025_DEFAULT_DO_NOT_USE_IN_PROD")
app.permanent_session_lifetime = timedelta(hours=8) # Sessions last for 8 hours

# Initialize the BlockchainClient for crypto payouts
blockchain_client = BlockchainClient()

# Initialize production security middleware
security_middleware = SecurityMiddleware(app)
production_config = get_production_config()

# Validate production configuration on startup
if not validate_production_config():
    logger.error("Production configuration validation failed. Please review production_config.py.")
    # In a strict production environment, this might prevent the app from starting.

# User roles for access control
ROLES = {
    'ADMIN': 'admin',
    'OPERATOR': 'operator'
}

# Default admin credentials (for initial setup/demo)
# In a real system, these would be managed securely, e.g., in a database.
DEFAULT_ADMIN = {
    'username': 'blackrockadmin',
    'password_hash': generate_password_hash('Br_3339'), # Default password set back to Br_3339
    'role': ROLES['ADMIN']
}

# --- Firebase Initialization (for Canvas environment and Render deployments) ---
# Global variables provided by the Canvas environment at runtime.
# For local development, you might need to mock them or provide a dummy config.
app_id = os.environ.get('__app_id', 'default-app-id') # Fallback for local testing
firebase_config_str = os.environ.get('__firebase_config', '{}') # Fallback for local testing
initial_auth_token = os.environ.get('__initial_auth_token', None) # Fallback for local testing

# Environment variable for service account key (for Render/non-Canvas deployments)
FIREBASE_SERVICE_ACCOUNT_KEY_BASE64 = os.environ.get('FIREBASE_SERVICE_ACCOUNT_KEY_BASE64')

db = None # Firestore client
firebase_auth = None # Firebase Auth client
current_user_id = None # Authenticated user ID (global)

def initialize_firebase():
    global db, firebase_auth, current_user_id # Declare global to modify them
    if not firebase_admin._apps: # Prevent re-initialization if already initialized
        if FIREBASE_SERVICE_ACCOUNT_KEY_BASE64:
            # Option 1: Initialize with service account key from environment variable (recommended for Render)
            try:
                service_account_info = json.loads(base64.b64decode(FIREBASE_SERVICE_ACCOUNT_KEY_BASE64).decode('utf-8'))
                cred = credentials.Certificate(service_account_info)
                firebase_admin.initialize_app(cred)
                db = firestore.client()
                firebase_auth = auth # Initialize auth client
                logger.info("Firebase Admin SDK initialized using service account key from environment variable.")
            except Exception as e:
                logger.error(f"Error initializing Firebase with service account key: {e}. Firestore will not be available.")
                db = None
                firebase_auth = None
        elif firebase_config_str:
            # Option 2: Initialize with Canvas-provided config (for Canvas-native deployments)
            try:
                firebase_config = json.loads(firebase_config_str)
                firebase_admin.initialize_app(options={'projectId': firebase_config.get('projectId')})
                db = firestore.client()
                firebase_auth = auth # Initialize auth client
                logger.info("Firebase Admin SDK initialized using Canvas-provided config.")
            except Exception as e:
                logger.error(f"Error initializing Firebase with Canvas config: {e}. Firestore will not be available.")
                db = None
                firebase_auth = None
        else:
            logger.warning("No Firebase config or service account key found in environment. Firestore will not be available.")
            db = None
            firebase_auth = None
    else: # If already initialized (e.g., in a reloader scenario in dev or if called multiple times)
        db = firestore.client()
        firebase_auth = auth
        logger.info("Firebase Admin SDK already initialized. Reusing existing clients.")


    # Set current_user_id after Firebase initialization attempt
    if db: # Only proceed with auth if db client was successfully initialized
        if initial_auth_token and firebase_auth:
            try:
                decoded_token = firebase_auth.verify_id_token(initial_auth_token)
                current_user_id = decoded_token['uid']
                logger.info(f"Signed in with custom token. User ID: {current_user_id}")
            except Exception as e:
                logger.error(f"Error verifying initial auth token: {e}. Signing in anonymously for Firestore.")
                current_user_id = f"anonymous_{os.urandom(16).hex()}" # Fallback anonymous ID
        else:
            current_user_id = f"anonymous_{os.urandom(16).hex()}" # Anonymous ID for local dev
            logger.info(f"No initial auth token. Signed in anonymously. User ID: {current_user_id}")
    else:
        current_user_id = None # Ensure user ID is None if Firebase init failed

# --- Firestore Helpers (defined after Firebase init) ---
def get_transactions_collection_ref():
    """Returns the Firestore collection reference for transactions."""
    if db and current_user_id:
        # Use a public collection path for simplicity in this demo, tied to app_id
        # For private user data, use: return db.collection(f"artifacts/{app_id}/users/{current_user_id}/transactions")
        return db.collection(f"artifacts/{app_id}/public/data/transactions")
    else:
        logger.error("Firestore DB or current_user_id not initialized. Cannot get collection reference.")
        # Return a dummy object or raise an error to prevent further Firestore operations
        class DummyCollectionRef:
            def document(self, doc_id): return self
            def set(self, data): pass
            def get(self): return type('obj', (object,), {'exists': False, 'to_dict': lambda: {}})()
            def stream(self): return []
            def order_by(self, *args, **kwargs): return self
            def limit(self, *args, **kwargs): return self
            def update(self, data): pass # Add update method for compatibility
            def add(self, data): pass # Add add method for compatibility
        return DummyCollectionRef()


def init_default_users():
    """
    Initializes default users (like the admin) if the user data file does not exist.
    In a production environment, user management would typically involve a database.
    """
    users_file = 'config/users.json'
    if not os.path.exists(users_file):
        os.makedirs('config', exist_ok=True) # Ensure the config directory exists
        with open(users_file, 'w') as f:
            json.dump({
                'blackrockadmin': DEFAULT_ADMIN
            }, f, indent=2)
        logger.info("Default admin user initialized.")

def get_users():
    """Retrieves user data from the users.json file."""
    users_file = 'config/users.json'
    if os.path.exists(users_file):
        with open(users_file, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    """Saves updated user data back to the users.json file."""
    users_file = 'config/users.json'
    with open(users_file, 'w') as f:
        json.dump(users, f, indent=2)

def login_required(role=None):
    """
    Decorator to enforce login and role-based access control for routes.
    Redirects to login if not authenticated, or to dashboard if insufficient permissions.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('logged_in'):
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
            
            if role and session.get('user_role') != role:
                flash('Insufficient permissions.', 'error')
                return redirect(url_for('dashboard')) # Redirect to a safe page like dashboard
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# New comprehensive setup function to ensure correct initialization order
def setup_application_components():
    """Performs all necessary application setup on startup."""
    initialize_firebase() # Call directly, as Flask's startup handles app.app_context()
    init_default_users() # Call the default user initialization

# Initialize the application components when the module is loaded
# This ensures default users are set up and Firebase is initialized
setup_application_components()

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.route('/')
def index():
    """Root URL redirects to login or dashboard based on session status."""
    if session.get('logged_in'):
        return render_template('index.html') # Render main terminal UI
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@audit_log("User Login Attempt") # Audit log decorator for login attempts
def login():
    """Handles user login authentication."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        users = get_users()
        user = users.get(username)
        
        if user and check_password_hash(user['password_hash'], password):
            session['logged_in'] = True
            session['username'] = username
            session['user_role'] = user['role']
            session['login_time'] = datetime.now().isoformat()
            
            logger.info(f"User {username} logged in with role {user['role']}")
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('index')) # Redirect to index (main terminal) after login
        else:
            flash('Invalid username or password.', 'error')
            logger.warning(f"Failed login attempt for username: {username}")
    
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Handles the 'Forgot Password' functionality.
    """
    # This route is currently a placeholder and does not implement TOTP secret generation.
    # If you need TOTP, you would integrate pyotp here as in previous versions.
    if request.method == 'POST':
        # In a real application, this would trigger an email or other reset mechanism
        flash('Password reset instructions sent to your email (simulated).', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/logout')
def logout():
    """Handles user logout, clearing the session."""
    username = session.get('username', 'Unknown')
    session.clear()
    flash(f'Goodbye, {username}!', 'info')
    logger.info(f"User {username} logged out")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required()
def dashboard():
    """Displays the main dashboard. Admin users see admin options."""
    user_role = session.get('user_role')
    
    if user_role == ROLES['ADMIN']:
        return render_template('admin_dashboard.html', 
                             username=session.get('username'))
    else:
        return redirect(url_for('index')) # Operators go directly to main terminal

@app.route('/admin/config', methods=['GET', 'POST'])
@login_required(role=ROLES['ADMIN'])
def admin_config():
    """
    Admin configuration management for payout wallets and transaction limits.
    This uses environment variables or default values now.
    """
    # Load current values from environment variables or defaults
    current_erc20_wallet = os.environ.get('DEFAULT_ERC20_WALLET', '0xDefaultERC20WalletAddressForTesting')
    current_trc20_wallet = os.environ.get('DEFAULT_TRC20_WALLET', 'TDefaultTRC20WalletAddressForTesting')
    current_daily_limit = int(os.environ.get('DAILY_LIMIT_PER_TERMINAL', '10000000')) # Default 10M

    if request.method == 'POST':
        try:
            # Update wallet addresses (these would update environment variables or a database in a real system)
            erc20_wallet = request.form.get('erc20_wallet', '').strip()
            trc20_wallet = request.form.get('trc20_wallet', '').strip()
            daily_limit_str = request.form.get('daily_limit', '10000000')
            
            # Validate wallet addresses
            if erc20_wallet and not (erc20_wallet.startswith('0x') and len(erc20_wallet) == 42):
                flash('Invalid ERC-20 wallet address format.', 'error')
                return redirect(url_for('admin_config'))
            
            if trc20_wallet and not (trc20_wallet.startswith('T') and len(trc20_wallet) >= 34):
                flash('Invalid TRC-20 wallet address format.', 'error')
                return redirect(url_for('admin_config'))
            
            daily_limit = int(daily_limit_str)
            if daily_limit <= 0:
                flash('Daily limit must be a positive number.', 'error')
                return redirect(url_for('admin_config'))

            logger.info(f"Admin {session.get('username')} updated ERC20 wallet to: {erc20_wallet}")
            logger.info(f"Admin {session.get('username')} updated TRC20 wallet to: {trc20_wallet}")
            logger.info(f"Admin {session.get('username')} updated Daily Limit to: {daily_limit}")

            current_erc20_wallet = erc20_wallet
            current_trc20_wallet = trc20_wallet
            current_daily_limit = daily_limit
            
            flash('Configuration updated successfully! (Note: Changes might require re-deployment for persistence)', 'success')
            
        except ValueError:
            flash('Invalid input for daily limit. Please enter a number.', 'error')
        except Exception as e:
            logger.error(f"Configuration update failed: {str(e)}")
            flash('Configuration update failed. Please check your inputs.', 'error')
    
    return render_template('admin_config.html', 
                           erc20_wallet=current_erc20_wallet,
                           trc20_wallet=current_trc20_wallet,
                           daily_limit=current_daily_limit)

@app.route('/protocol', methods=['GET', 'POST'])
@login_required()
def protocol():
    """Allows selection of the payment protocol."""
    PROTOCOLS = {
        "POS Terminal -101.1 (4-digit approval)": 4,
        "POS Terminal -101.4 (6-digit approval)": 6,
        "POS Terminal -101.6 (Pre-authorization)": 6,
        "POS Terminal -101.7 (4-digit approval)": 4,
        "POS Terminal -101.8 (PIN-LESS transaction)": 4,
        "POS Terminal -201.1 (6-digit approval)": 6,
        "POS Terminal -201.3 (6-digit approval)": 6,
        "POS Terminal -201.5 (6-digit approval)": 6
    }
    if request.method == 'POST':
        protocol = request.form.get('protocol')
        if protocol:
            session['protocol'] = protocol
            session['transaction_start'] = datetime.now().isoformat()
            session['code_length'] = PROTOCOLS.get(protocol, 6) 
            logger.info(f"Protocol selected: {protocol}")
            return redirect(url_for('amount'))
        else:
            flash('Please select a protocol.', 'error')
    
    return render_template('protocol.html', protocols=PROTOCOLS.keys())

@app.route('/amount', methods=['GET', 'POST'])
@login_required()
def amount():
    """Allows input of the transaction amount and currency."""
    DAILY_LIMIT_PER_TERMINAL = int(os.environ.get('DAILY_LIMIT_PER_TERMINAL', '10000000')) # Default 10M

    if request.method == 'POST':
        amount_str = request.form.get('amount', '').replace(',', '').strip()
        currency = request.form.get('currency')

        if not currency or currency not in ['USD', 'EUR']:
            flash("Please select a valid currency.", "error")
            return render_template('amount.html')
        
        try:
            amount_float = float(amount_str)
            if amount_float <= 0:
                flash("Amount must be a positive number.", "error")
                return render_template('amount.html')

            current_date = date.today()
            last_txn_date_str = session.get('last_transaction_date')

            if last_txn_date_str and date.fromisoformat(last_txn_date_str) < current_date:
                session['daily_amount_spent'] = 0.0
                session['last_transaction_date'] = current_date.isoformat()

            current_spent = session.get('daily_amount_spent', 0.0)
            if (current_spent + amount_float) > DAILY_LIMIT_PER_TERMINAL:
                flash(f"Daily transaction limit of {DAILY_LIMIT_PER_TERMINAL:,.2f} {currency} exceeded for this terminal.", "error")
                return render_template('amount.html')

            session['amount'] = amount_str
            session['currency'] = currency
            session['daily_amount_spent'] = current_spent + amount_float

            logger.info(f"Amount set: {amount_str} {currency}")
            return redirect(url_for('payout'))
            
        except ValueError:
            flash('Please enter a valid amount.', 'error')
    
    default_amount = os.environ.get('DEFAULT_TRANSACTION_AMOUNT', '1000000') # Default 1M
    return render_template('amount.html', default_amount=default_amount)

@app.route('/payout', methods=['GET', 'POST'])
@login_required()
def payout():
    """Allows selection of the crypto payout method and wallet."""
    default_erc20_wallet = os.environ.get('DEFAULT_ERC20_WALLET', '0xDefaultERC20WalletAddressForTesting')
    default_trc20_wallet = os.environ.get('DEFAULT_TRC20_WALLET', 'TDefaultTRC20WalletAddressForTesting')

    if request.method == 'POST':
        method = request.form['method']
        custom_wallet = request.form.get('custom_wallet', '').strip()

        if method == 'ERC20':
            wallet = custom_wallet if custom_wallet else default_erc20_wallet
            if custom_wallet and not (wallet.startswith('0x') and len(wallet) == 42):
                flash('Invalid ERC-20 wallet address format.', 'error')
                return redirect(url_for('payout'))
            session['payout_type'] = 'ERC20'
            session['wallet'] = wallet
            
        elif method == 'TRC20':
            wallet = custom_wallet if custom_wallet else default_trc20_wallet
            if custom_wallet and not (wallet.startswith('T') and len(wallet) >= 34):
                flash('Invalid TRC-20 wallet address format.', 'error')
                return redirect(url_for('payout'))
            session['payout_type'] = 'TRC20'
            session['wallet'] = wallet
        
        else:
            flash('Please select a payout method.', 'error')
            return redirect(url_for('payout'))
        
        logger.info(f"Payout method selected: {method}, Wallet: {session['wallet'][:10]}...")
        return redirect(url_for('card'))
    
    return render_template('payout.html',
                           default_erc20_wallet=default_erc20_wallet,
                           default_trc20_wallet=default_trc20_wallet)

@app.route('/card', methods=['GET', 'POST'])
@login_required()
def card():
    """Allows input of card details."""
    if request.method == 'POST':
        pan = request.form['pan'].replace(" ", "").replace("-", "")
        exp = request.form['expiry'].replace("/", "")
        cvv = request.form['cvv']
        
        if not validate_card_number(pan):
            flash('Invalid card number format.', 'error')
            return redirect(url_for('card'))
        
        if not re.match(r'^\d{4}$', exp):
            flash('Invalid expiry date format (MMYY).', 'error')
            return redirect(url_for('card'))
        
        if not re.match(r'^\d{3,4}$', cvv):
            flash('Invalid CVV format.', 'error')
            return redirect(url_for('card'))

        session.update({'pan': pan, 'exp': exp, 'cvv': cvv})

        if pan.startswith("4"):
            session['card_type'] = "VISA"
        elif pan.startswith("5"):
            session['card_type'] = "MASTERCARD"
        elif pan.startswith("3"):
            session['card_type'] = "AMEX"
        elif pan.startswith("6"):
            session['card_type'] = "DISCOVER"
        else:
            session['card_type'] = "UNKNOWN"
        
        logger.info(f"Card entered: {session['card_type']} ending in {pan[-4:]}")
        # Redirect to the auth route for manual code entry
        return redirect(url_for('auth'))
    
    return render_template('card.html')

@app.route('/auth', methods=['GET', 'POST'])
@login_required()
def auth():
    """
    Handles the manual input of the authorization code and triggers the ISO transaction process.
    """
    expected_length = session.get('code_length', 6) 
    
    if request.method == 'POST':
        # This block executes when the user submits the manual auth code form
        code = request.form.get('auth', '') # Get the manually entered auth code
        
        if len(code) != expected_length or not code.isdigit():
            flash(f"Authorization code must be {expected_length} digits and numeric.", "error")
            return render_template('auth.html', code_length=expected_length, warning=f"Code must be {expected_length} digits and numeric.")

        session['auth_code'] = code # Store the user's manual auth code in session

        # Prepare data for ISO 8583 message (as a dictionary)
        iso_request_data = {
            'mti': '0100',  # Authorization Request
            'pan': session.get('pan'),
            'amount': int(float(session.get('amount')) * 100), # Amount in cents/smallest unit
            'expiry': session.get('exp'),
            'cvv': session.get('cvv'),
            'auth_code': session.get('auth_code'), # Use the user's manually entered auth code here
            'transaction_id': generate_transaction_id(), # Generate a new ID for the ISO message
            'currency_code': '840' if session.get('currency') == 'USD' else '978', # ISO 4217 for USD/EUR
            'protocol_type': session.get('protocol')
        }

        # Get ISO server details from environment variables
        ISO_SERVER_HOST = os.environ.get('ISO_SERVER_HOST', '66.185.176.0') # Default for demo, must be real in prod
        ISO_SERVER_PORT = int(os.environ.get('ISO_SERVER_PORT', 20)) # Default for demo, must be real in prod
        ISO_TIMEOUT = int(os.environ.get('ISO_TIMEOUT', 60)) # Timeout for socket connection

        logger.info(f"Attempting direct ISO 8583 connection to {ISO_SERVER_HOST}:{ISO_SERVER_PORT}...")
        iso_response = {}
        try:
            # Create a socket connection
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(ISO_TIMEOUT)
                sock.connect((ISO_SERVER_HOST, ISO_SERVER_PORT))
                logger.info("Connected to ISO 8583 server.")

                # --- Build ISO 8583 Message (JSON payload with 2-byte length header) ---
                # This logic assumes the target ISO 8583 server expects a JSON payload
                # wrapped with a 2-byte length header over the TCP socket.
                # In a real-world scenario with a standard ISO 8583 processor,
                # you would use a dedicated Python ISO 8583 library (e.g., py8583)
                # to pack the MTI, bitmap, and data elements into a binary message.
                # For this demo, we're sending JSON for simplicity, assuming the
                # external server (or a mock one like server.py) understands it.

                # Convert dict to JSON string, then encode to bytes
                json_payload = json.dumps(iso_request_data)
                message_body = json_payload.encode('utf-8')
                
                # Prepend with 2-byte length header (big-endian unsigned short)
                # This is a common practice for ISO 8583 over TCP
                message_length = len(message_body)
                length_header = struct.pack('!H', message_length) # !H means network byte order (big-endian) unsigned short

                full_message = length_header + message_body
                
                logger.info(f"Sending {len(full_message)} bytes to ISO server (payload length: {message_length})...")
                sock.sendall(full_message)

                # --- Receive ISO 8583 Response ---
                # First, read the 2-byte length header of the response
                response_length_header = sock.recv(2)
                if not response_length_header:
                    raise ConnectionError("Did not receive length header from ISO server.")
                response_length = struct.unpack('!H', response_length_header)[0]
                
                # Read the actual response body based on the length
                response_body = b''
                bytes_received = 0
                while bytes_received < response_length:
                    chunk = sock.recv(response_length - bytes_received)
                    if not chunk:
                        logger.error("ISO server disconnected while reading response body.")
                        break
                    response_body += chunk
                    bytes_received += len(chunk)

                if bytes_received != response_length:
                    logger.error(f"Incomplete response received from ISO server. Expected {response_length}, got {bytes_received}.")
                    raise ConnectionError("Incomplete response from ISO server.")

                # Assuming the response is also JSON wrapped in a length header
                iso_response_json = response_body.decode('utf-8')
                iso_response = json.loads(iso_response_json)
                logger.info(f"Received response from ISO 8583 server: {iso_response}")

        except socket.timeout:
            logger.error(f"ISO 8583 server connection timed out after {ISO_TIMEOUT} seconds.")
            iso_response = {'status': 'ERROR', 'message': 'ISO Server Timeout', 'field39': '99'}
        except ConnectionRefusedError:
            logger.error(f"Connection to ISO 8583 server refused at {ISO_SERVER_HOST}:{ISO_SERVER_PORT}. Is the server running and accessible?")
            iso_response = {'status': 'ERROR', 'message': 'Connection Refused (Server not reachable)', 'field39': '99'}
        except socket.error as e:
            logger.error(f"Socket error during ISO 8583 communication: {e}", exc_info=True)
            iso_response = {'status': 'ERROR', 'message': f'Socket Error: {e}', 'field39': '99'}
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON response from ISO 8583 server: {iso_response_json}", exc_info=True)
            iso_response = {'status': 'ERROR', 'message': 'Invalid Server Response Format', 'field39': '99'}
        except Exception as e:
            logger.critical(f"Critical error during ISO 8583 communication: {e}", exc_info=True)
            iso_response = {'status': 'ERROR', 'message': f'Unexpected ISO Communication Error: {e}', 'field39': '99'}

        status = iso_response.get('status', 'Declined')
        auth_code_from_iso = iso_response.get('auth_code') # This is the auth code returned by the ISO server
        message = iso_response.get('message', 'Unknown error.')
        field39_resp = iso_response.get('field39', 'XX') # ISO 8583 Field 39 Response Code

        current_transaction_details = {
            'transaction_id': iso_request_data['transaction_id'],
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'card_number': session.get('pan'),
            'amount': float(session.get('amount')),
            'currency': session.get('currency'),
            'protocol_type': session.get('protocol'),
            'crypto_network_type': session.get('payout_type'),
            'status': status,
            'payout_status': None,
            'crypto_payout_amount': 0.0,
            'simulated_gas_fee': 0.0,
            'crypto_address': '',
            'iso_field39': field39_resp,
            'message': message,
            'iso_auth_code': auth_code_from_iso, # Store the auth code received from ISO server for records
            'entered_auth_code': code # Store the code manually entered by the user
        }

        # Store initial transaction in Firestore for persistence
        if db:
            try:
                get_transactions_collection_ref().document(current_transaction_details['transaction_id']).set(current_transaction_details)
                logger.info(f"Firestore: Stored transaction {current_transaction_details['transaction_id']} with status {status}")
            except Exception as e:
                logger.error(f"Firestore Error: Could not store transaction {current_transaction_details['transaction_id']}: {e}")
                flash("Failed to log transaction to history.", "warning")
        else:
            logger.warning("Firestore not initialized. Transaction logging skipped.")

        # Proceed directly to success or reject screen based on ISO response
        if status == 'Approved':
            # If approved by ISO, proceed with crypto payout
            recipient_wallet_info = get_wallet_config(current_transaction_details['crypto_network_type'])
            recipient_crypto_address = recipient_wallet_info['address']

            # Call the real blockchain_client to send USDT
            crypto_payout_result = blockchain_client.send_usdt(
                network=current_transaction_details['crypto_network_type'].lower(),
                to_address=recipient_crypto_address,
                amount_usd=current_transaction_details['amount']
            )

            current_transaction_details['crypto_payout_amount'] = crypto_payout_result.get('payout_amount_usdt', 0.0)
            current_transaction_details['simulated_gas_fee'] = crypto_payout_result.get('simulated_gas_fee_usdt', 0.0)
            current_transaction_details['payout_status'] = crypto_payout_result.get('status')
            current_transaction_details['status'] = 'Completed' if crypto_payout_result.get('status') == 'Success' else 'Payout Failed'
            current_transaction_details['crypto_address'] = recipient_crypto_address
            current_transaction_details['blockchain_hash'] = crypto_payout_result.get('transaction_hash', 'N/A') # Use 'transaction_hash' from isocrypto.py
            current_transaction_details['message'] = crypto_payout_result.get('message', 'Payment and Crypto Payout Completed.')

            # Update transaction in Firestore with payout details
            if db:
                try:
                    get_transactions_collection_ref().document(current_transaction_details['transaction_id']).update(current_transaction_details)
                    logger.info(f"Firestore: Updated completed transaction {current_transaction_details['transaction_id']} with payout status {current_transaction_details['payout_status']}")
                except Exception as e:
                    logger.error(f"Firestore Error: Could not update completed transaction {current_transaction_details['transaction_id']}: {e}")
                    flash("Failed to update transaction history with payout details.", "warning")

            if current_transaction_details['status'] == 'Completed':
                flash("Payment Approved and Payout Initiated!", "success")
                return redirect(url_for('success_screen', transaction_id=current_transaction_details['transaction_id']))
            else:
                flash(f"Payment Approved, but Payout Failed: {current_transaction_details['message']}", "warning")
                return redirect(url_for('reject_screen', transaction_id=current_transaction_details['transaction_id']))
        else:
            # If ISO server declined, go to reject screen
            flash(f'Payment {status}: {message}', 'error')
            return redirect(url_for('reject_screen', transaction_id=current_transaction_details['transaction_id']))

    # This block executes for GET request to /auth
    return render_template('auth.html', code_length=expected_length)

# --- Helper function for retrieving transaction details from Firestore ---
def get_transaction_details_from_firestore(transaction_id):
    """Retrieves transaction details from Firestore."""
    if db:
        try:
            doc_ref = get_transactions_collection_ref().document(transaction_id)
            doc = doc_ref.get()
            if doc.exists:
                return doc.to_dict()
        except Exception as e:
            logger.error(f"Firestore Error: Could not retrieve transaction {transaction_id}: {e}")
    return None

# Removed the /auth_code_entry/<transaction_id> and /complete_payment routes
# as the manual auth code entry now happens directly on the /auth page.

@app.route('/success')
@login_required()
def success_screen():
    """Renders the success screen with transaction details."""
    transaction_id = request.args.get('transaction_id')
    transaction = get_transaction_details_from_firestore(transaction_id)

    if not transaction:
        flash('Transaction details not found.', 'error')
        return redirect(url_for('index'))

    return render_template('success.html', transaction=transaction)

@app.route('/reject')
@login_required()
def reject_screen():
    """Renders the reject screen with transaction details."""
    transaction_id = request.args.get('transaction_id')
    transaction = get_transaction_details_from_firestore(transaction_id)

    if not transaction:
        flash('Transaction details not found.', 'error')
        return redirect(url_for('index'))

    return render_template('reject.html', transaction=transaction)

@app.route('/transaction_history')
@login_required()
def transaction_history_screen():
    """Renders the transaction history screen."""
    transactions = []
    if db:
        try:
            # Fetch all documents from the transactions collection, ordered by timestamp
            docs = get_transactions_collection_ref().order_by('timestamp', direction=firestore.Query.DESCENDING).limit(100).stream()
            for doc in docs:
                txn = doc.to_dict()
                # Convert Firestore Timestamp object to a readable string for display
                if 'timestamp' in txn and hasattr(txn['timestamp'], 'strftime'):
                    txn['timestamp'] = txn['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                transactions.append(txn)
            logger.info(f"Firestore: Fetched {len(transactions)} transactions for history.")
        except Exception as e:
            logger.error(f"Firestore Error: Could not fetch transaction history: {e}")
            flash('Error loading transaction history.', 'error')
    else:
        flash('Firestore not initialized. Transaction history not available.', 'warning')

    return render_template('transaction_history.html', transactions=transactions)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
