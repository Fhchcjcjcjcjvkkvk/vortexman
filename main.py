from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit
from supabase import create_client, Client
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
from ecdsa import SigningKey, VerifyingKey, NIST384p
import hashlib
from time import sleep
from threading import Timer
from werkzeug.security import generate_password_hash, check_password_hash
from ecdsa import NIST384p, SigningKey, VerifyingKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import timedelta

# Function to generate fresh ECDH keys (private and public)
def generate_fresh_ecdh_keys():
    sk = SigningKey.generate(curve=NIST384p)
    vk = sk.get_verifying_key()
    private_key = sk.to_pem()
    public_key = vk.to_pem()
    return private_key, public_key

# Function to generate ECDH keys (private and public)
def generate_ecdh_keys():
    sk = SigningKey.generate(curve=NIST384p)
    vk = sk.get_verifying_key()
    private_key = sk.to_pem()
    public_key = vk.to_pem()
    return private_key, public_key

# Function to compute the shared secret from the other party's public key
def compute_shared_secret(private_key, other_public_key):
    sk = SigningKey.from_pem(private_key)
    vk = VerifyingKey.from_pem(other_public_key)
    shared_secret = sk.exchange(vk)
    return shared_secret

# Derive AES key from shared secret
def derive_aes_key(shared_secret):
    # Use PBKDF2 to derive the AES key from the shared secret
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=os.urandom(16),  # Ensure a unique salt
        length=32,  # Length of AES-256 key (32 bytes)
        iterations=100000
    )
    return kdf.derive(shared_secret)



app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app)

# Supabase setup
url = "https://uqwylxwxnxasfrrxmcsp.supabase.co"
key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVxd3lseHd4bnhhc2ZycnhtY3NwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzY0OTYzMTIsImV4cCI6MjA1MjA3MjMxMn0.63rctEDbwaOhRu8D2yM2z3XFoklTfcrN7VQzKNfJozY"  # Replace with your actual Supabase key
supabase: Client = create_client(url, key)

# Room code
ROOM_CODE = "45784656"


# Load or generate AES key (256-bit)
def load_or_generate_aes_key():
    try:
        key_path = 'static/key/aes_key.key'
        if not os.path.exists(key_path):
            print("AES key not found, generating new one...")
            key = os.urandom(32)  # 256-bit key for AES-256
            with open(key_path, 'wb') as key_file:
                key_file.write(key)
        else:
            with open(key_path, 'rb') as key_file:
                key = key_file.read()
        return key
    except Exception as e:
        print(f"Error loading or generating AES key: {e}")
        return None


# Encrypt a message using AES-GCM
def encrypt_message_aes(message, aes_key):
    try:
        nonce = os.urandom(12)  # AES-GCM requires a 12-byte nonce
        cipher = Cipher(algorithms.AES(aes_key),
                        modes.GCM(nonce),
                        backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad message to ensure it's a multiple of the block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(
            message.encode('utf-8')) + padder.finalize()

        # Encrypt the padded message
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Return the ciphertext, nonce, and tag
        return base64.b64encode(ciphertext), base64.b64encode(
            nonce), base64.b64encode(encryptor.tag)
    except Exception as e:
        print(f"Error encrypting message: {e}")
        return None, None, None

def decrypt_message_aes(encrypted_message, nonce, tag, aes_key):
    try:
        cipher = Cipher(algorithms.AES(aes_key),
                        modes.GCM(base64.b64decode(nonce),
                                  base64.b64decode(tag)),
                        backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the message
        decrypted_data = decryptor.update(
            base64.b64decode(encrypted_message)) + decryptor.finalize()

        # Unpad the decrypted message
        unpadder = padding.PKCS7(128).unpadder()
        original_message = unpadder.update(
            decrypted_data) + unpadder.finalize()

        return original_message.decode('utf-8')
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return None

# Generate private and public keys for EDSA
def generate_edsa_keys():
    if not os.path.exists("private_key.pem") or not os.path.exists(
            "public_key.pem"):
        print("Keys not found, generating new keys...")
        sk = SigningKey.generate(curve=NIST384p)
        vk = sk.get_verifying_key()

        with open("private_key.pem", "wb") as f:
            f.write(sk.to_pem())

        with open("public_key.pem", "wb") as f:
            f.write(vk.to_pem())
        print("Keys generated and saved.")
    else:
        print("Keys already exist.")


generate_edsa_keys()


# Sign message with private key
def sign_message(message, private_key_path="private_key.pem"):
    with open(private_key_path, "rb") as f:
        private_key = SigningKey.from_pem(f.read())
    signature = private_key.sign(message.encode('utf-8'))
    return signature

# Encrypt and store message in Supabase with signature
def encrypt_and_store_message(message, aes_key, username):
    try:
        encrypted_message, nonce, tag = encrypt_message_aes(message, aes_key)

        if encrypted_message is None:
            print("Error: Encryption failed.")
            return

        # Sign the message
        signature = sign_message(message)

        # Store encrypted message, nonce, tag, and signature in Supabase
        response = supabase.table('vortex').insert({
            'user': username,
            'message': encrypted_message.decode('utf-8'),
            'nonce': nonce.decode('utf-8'),
            'tag': tag.decode('utf-8'),
            'signature': signature.hex()
        }).execute()

        if hasattr(response, 'error') and response.error:
            print(f"Error inserting message: {response.error['message']}")
        elif hasattr(response, 'data') and response.data:
            print("Message successfully stored in Supabase.")
        else:
            print("No data returned from Supabase.")
    except Exception as e:
        print(f"Error storing message in Supabase: {e}")

# Fetch and decrypt messages from Supabase
def fetch_messages(aes_key):
    try:
        response = supabase.table('vortex').select('*').execute()

        if not response.data:
            print("No messages found in Supabase.")
            return []

        messages = []
        for record in response.data:
            try:
                decrypted_message = decrypt_message_aes(
                    record['message'], record['nonce'], record['tag'], aes_key)
                if decrypted_message:
                    # Verify the message's signature
                    signature = bytes.fromhex(record['signature'])
                    if verify_signature(decrypted_message, signature):
                        messages.append({
                            'user': record['user'],
                            'message': decrypted_message
                        })
                    else:
                        print(
                            f"Signature verification failed for message: {decrypted_message}"
                        )
            except Exception as e:
                print(f"Error decrypting message: {e}")

        return messages

    except Exception as e:
        print(f"Error fetching messages from Supabase: {e}")
        return []


# Verify signature with public key
def verify_signature(message, signature, public_key_path="public_key.pem"):
    with open(public_key_path, "rb") as f:
        public_key = VerifyingKey.from_pem(f.read())
    try:
        public_key.verify(signature, message.encode('utf-8'))
        return True
    except:
        return False


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash the password before storing
        hashed_password = generate_password_hash(password)

        # Check if the username already exists
        response = supabase.table('users').select('username').eq(
            'username', username).execute()
        if response.data:
            return "Username already exists", 400

        # Insert new user into the database with the hashed password
        response = supabase.table('users').insert({
            'username': username,
            'password': hashed_password
        }).execute()

        if hasattr(response, 'error') and response.error:
            return f"Error: {response.error['message']}", 500
        else:
            return redirect(url_for(
                'login'))  # Redirect to login after successful registration

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if the user is already logged in by looking for the cookie
    username = request.cookies.get('username')
    if username:
        session['user'] = username
        return redirect(url_for('enter_room'))  # User is already logged in

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if username exists in the database
        response = supabase.table('users').select('*').eq(
            'username', username).execute()
        if response.data:
            user = response.data[0]
            if check_password_hash(user['password'], password):  # Verify hashed password
                session['user'] = username
                # Set a persistent cookie (e.g., for 1 week)
                resp = redirect(url_for('enter_room'))
                resp.set_cookie('username', username, max_age=timedelta(days=7))  # Store cookie
                return resp
            else:
                return "Invalid credentials", 401
        else:
            return "Invalid credentials", 401

    return render_template('login.html')

@app.route('/enter_room', methods=['GET', 'POST'])
def enter_room():
    if request.method == 'POST':
        entered_code = request.form['room_code']
        if entered_code == ROOM_CODE:
            session['room_access'] = True
            return redirect(url_for('chat'))
        else:
            return "Invalid room code. Please try again.", 401
    return render_template('enter_room.html')


@app.route('/chat')
def chat():
    try:
        if 'user' not in session:
            return redirect(url_for('login'))
        if not session.get('room_access', False):
            return redirect(url_for('enter_room'))

        aes_key = load_or_generate_aes_key()
        if aes_key is None:
            return "Error loading encryption key", 500

        messages = fetch_messages(aes_key)
        return render_template('chat.html',
                               username=session['user'],
                               messages=messages)

    except Exception as e:
        print(f"Error in /chat route: {e}")
        return "Internal Server Error", 500


@app.route('/k', methods=['GET', 'POST'])
def self_destruction():
    if 'user' not in session:
        return redirect(url_for('login'))

    if not session.get('room_access', False):
        return redirect(url_for('enter_room'))

    if request.method == 'POST':
        destruction_time = int(request.form['destruction_time'])
        aes_key = load_or_generate_aes_key()
        if aes_key is None:
            return "Error loading encryption key", 500

        Timer(destruction_time, destroy_messages, [aes_key]).start()
        return render_template('destruct.html',
                               destruction_time=destruction_time)

    return render_template('destruct.html')


def destroy_messages(aes_key):
    try:
        response = supabase.table('vortex').delete().neq('user', '').execute()

        if hasattr(response, 'error') and response.error:
            print(f"Error deleting messages: {response.error['message']}")
        else:
            print("All messages successfully deleted.")
    except Exception as e:
        print(f"Error deleting messages: {e}")


@socketio.on('send_message')
def handle_message(data):
    try:
        message = data['message']
        username = data['username']

        signature = sign_message(message)

        aes_key = load_or_generate_aes_key()
        if aes_key is None:
            print("Error: AES key could not be loaded.")
            return

        encrypt_and_store_message(message, aes_key, username)

        emit('receive_message', {
            'username': username,
            'message': message,
            'signature': signature.hex()
        },
             broadcast=True)
    except Exception as e:
        print(f"Error handling message: {e}")


@socketio.on('join_chat')
def handle_join(username):
    emit('chat_event', {
        'username': username,
        'event': 'joined'
    },
         broadcast=True)


@socketio.on('leave_chat')
def handle_leave(username):
    emit('chat_event', {'username': username, 'event': 'left'}, broadcast=True)


@socketio.on('typing')
def handle_typing(username):
    emit('typing_event', {'username': username}, broadcast=True)
    sleep(3)
    emit('typing_event', {'username': None}, broadcast=True)

@socketio.on('exchange_public_keys')
def handle_key_exchange(data):
    try:
        username = data['username']
        public_key = data['public_key']  # Received public key

        # Generate a new ECDH key pair for the local user (ensures PFS)
        private_key, public_key = generate_fresh_ecdh_keys()
        session['private_key'] = private_key
        session['public_key'] = public_key

        # Store the public key of the other party
        session['other_public_key'] = public_key

        # Generate the shared secret
        shared_secret = compute_shared_secret(private_key, public_key)

        # Derive the AES key from the shared secret
        aes_key = derive_aes_key(shared_secret)

        # Store the AES key for secure communication
        session['aes_key'] = aes_key

        emit('key_exchange_complete', {'username': username}, broadcast=True)

    except Exception as e:
        print(f"Error in key exchange: {e}")

@socketio.on('send_public_key')
def handle_send_public_key(data):
    # Generate fresh ECDH key pair for each session
    private_key, public_key = generate_fresh_ecdh_keys()
    session['private_key'] = private_key  # Store private key in the session
    session['public_key'] = public_key    # Store public key in the session
    emit('exchange_public_keys', {'public_key': public_key})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
