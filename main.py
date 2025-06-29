# main.py

from flask import Flask, render_template, Response, request, jsonify
import time, threading, re, hashlib, random, datetime, pickle, os, base64, hmac, math, logging, html, json
from encrypt import RSA_SYSTEM, AES_SYSTEM
import shutil
import base64
from security import check, deep_sanitize, validate_aes_params
app = Flask(__name__)
update_event = threading.Condition()
users = {}


logging.basicConfig(level=logging.ERROR)

def ensure_public_keys():
    os.makedirs("static", exist_ok=True)
    shutil.copy("saves/public/rsa_e.key", "static/rsa_e.key")
    shutil.copy("saves/public/rsa_n.key", "static/rsa_n.key")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/security', methods=['POST'])
def handle_encryptedkey():
    """
        # Exclude encrypted fields from sanitization because they contain encrypted binary data
        # which could be corrupted if altered by sanitization routines.
        excluded = {"encrypted_key", "iv", "sbox"}
        data = request.get_json(force=True)
        data = deep_sanitize(data, rules=["html", "sql", "security"], exclude_keys=excluded)
        - iv: RSA-encrypted AES IV (hex string)
        - sbox: RSA-encrypted AES SBOX (hex string)
        - key_size: AES key size (128, 192, or 256)
        - metadata: dict with at least 'id' (user ID) and 'timestamp'

    Returns:
        - JSON response confirming key receipt or describing errors.
    """
    try:
        # Skip sanitizing encrypted fields
        excluded = {"encrypted_key", "iv", "sbox"}
        data = request.get_json(force=True)
        data = deep_sanitize(data, rules=["html", "sql", "security"], exclude_keys=excluded)


        # old: data = request.get_json(force=True)
        if not data or 'encrypted_key' not in data:
            return jsonify({'error': 'Missing encrypted_key'}), 400

        # Validate metadata
        metadata = data.get('metadata', {})
        if not isinstance(metadata, dict):
            return jsonify({'error': 'Invalid metadata'}), 400
        userID = metadata.get('id')
        timestamp = metadata.get('timestamp', '')
        if not userID:
            return jsonify({'error': 'Missing user ID'}), 400

        # Initialize user if not exists
        if userID not in users:
            users[userID] = {
                "message": "",
                "lastmessage": "",
                "name": "",
                "location": "home",
                "joined": False
            }

        # Validate and decrypt encrypted_key
        try:
            encrypted_key = int(data['encrypted_key'], 16)
            aes_key_bytes = RSA.rsa_decryption(encrypted_key)
        except Exception as e:
            logging.error(f"Key decryption failed: {e}")
            return jsonify({'error': 'Key decryption failed'}), 400

        # Validate and decrypt IV
        try:
            iv_hex = data.get('iv', '')
            if not iv_hex:
                return jsonify({'error': 'Missing IV'}), 400
            aes_iv = RSA.rsa_decryption(int(iv_hex, 16))
        except Exception as e:
            logging.error(f"IV decryption failed: {e}")
            return jsonify({'error': 'IV decryption failed'}), 400

        # Validate and decrypt SBOX
        try:
            sbox_hex = data.get('sbox', '')
            if not sbox_hex:
                return jsonify({'error': 'Missing SBOX'}), 400
            aes_sbox = RSA.rsa_decryption(int(sbox_hex, 16))
        except Exception as e:
            logging.error(f"SBOX decryption failed: {e}")
            return jsonify({'error': 'SBOX decryption failed'}), 400

        aes_size = data.get('key_size', 256)
        if not isinstance(aes_size, int) or aes_size not in (128, 192, 256):
            return jsonify({'error': 'Invalid key size'}), 400

        # Convert key and IV to arrays
        if isinstance(aes_key_bytes, str):
            aes_key_bytes = aes_key_bytes.encode('latin1')
        key_array = list(aes_key_bytes)

        if isinstance(aes_iv, str):
            try:
                iv_array = [int(aes_iv[i:i+2], 16) for i in range(0, len(aes_iv), 2)]
            except Exception:
                return jsonify({'error': 'Invalid IV format'}), 400
        else:
            iv_array = list(aes_iv)

        # SBOX processing
        if isinstance(aes_sbox, bytes):
            try:
                aes_sbox = aes_sbox.decode('utf-8')
            except Exception:
                return jsonify({'error': 'Invalid SBOX encoding'}), 400

        # Check SBOX length based on its type
        if isinstance(aes_sbox, str):
            if len(aes_sbox) != 512:
                return jsonify({'error': f'SBOX hex string is not the correct length: {len(aes_sbox)}'}), 400
            try:
                sbox_list = [int(aes_sbox[i:i+2], 16) for i in range(0, 512, 2)]
            except Exception:
                return jsonify({'error': 'Invalid SBOX format'}), 400
        elif isinstance(aes_sbox, (bytes, bytearray, list)):
            if len(aes_sbox) != 256:
                return jsonify({'error': f'SBOX bytes/list is not the correct length: {len(aes_sbox)}'}), 400
            sbox_list = list(aes_sbox)
        else:
            return jsonify({'error': 'Invalid SBOX type'}), 400

        sbox = {i: sbox_list[i] for i in range(256)}
        inv_sbox = {v: k for k, v in sbox.items()}

        # Only allow existing users to set keys
        if not isinstance(sbox_list, list):
            return jsonify({'error': 'Failed to parse AES SBOX'}), 400
        if len(sbox_list) != 256:
            return jsonify({'error': f'AES SBOX must have 256 entries, got {len(sbox_list)}'}), 400
        # Validate AES parameters
        if not isinstance(aes_key_bytes, (bytes, bytearray)):
            return jsonify({'error': 'Invalid AES key format'}), 400
        if not isinstance(iv_array, list):
            return jsonify({'error': 'Invalid AES IV format'}), 400
        if not isinstance(sbox_list, list) or len(sbox_list) != 256:
            return jsonify({'error': 'Invalid AES SBOX format'}), 400
        if not isinstance(aes_size, int) or aes_size not in (128, 192, 256):
            return jsonify({'error': 'Invalid key size'}), 400
        
        error = validate_aes_params(aes_key_bytes, iv_array, sbox_list, aes_size)
        if error:
            return error
        
        # Only update and save if parameters have changed
        existing_aes = users[userID].get("aes")
        existing_aes = users[userID].get("aes")
        should_save = False
        if not existing_aes or (
            existing_aes.key != key_array or
            existing_aes.iv != iv_array or
            existing_aes.sbox != sbox or
            existing_aes.inv_sbox != inv_sbox or
            existing_aes.round_keys != AES_SYSTEM(userID[:32], aes_size)._expand_key(key_array)
        ):
            users[userID]["aes"] = AES_SYSTEM(userID[:32], aes_size)
            users[userID]["aes"].key = key_array
            users[userID]["aes"].iv = iv_array
            users[userID]["aes"].sbox = sbox
            users[userID]["aes"].inv_sbox = inv_sbox
            users[userID]["aes"].round_keys = users[userID]["aes"]._expand_key(key_array)
            users[userID]["aes"].save()
        users[userID]["aes"].round_keys = users[userID]["aes"]._expand_key(key_array)
        users[userID]["aes"].save()

        logging.info(f"Received AES key for user {userID} at {timestamp}")
        response = {'reply': f"AES KEY CONFIRMED: Timestamp: {timestamp}"}
        return jsonify(response)
    except Exception as e:
        logging.error(f"Unexpected error in /api/security: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def read_html_file(file_path,user_id):
    try:
        with open("pageTemplates/"+file_path, 'r', encoding='utf-8') as file:
            return file.read().replace('\n','')
    except FileNotFoundError:
        return "Error: File not found."
    except Exception as e:
        return f"Error: {e}"


def generate(user_id):
    """Function to stream updates only when a change occurs."""
    last_msg = users[user_id]["lastmessage"]
    
    while True:
        with update_event:
            update_event.wait()  # Sleep until an update occurs
            new_msg = inject(users[user_id]["message"], user_id)
            sh_msg = get_hash(new_msg)

            if sh_msg != last_msg:  # Only send if it's new
                users[user_id]["lastmessage"] = sh_msg
                last_msg = sh_msg  # Update last message reference
                yield f"data: {new_msg}\n\n"  # Send to frontend

def inject(data, user_id):
    return data

def get_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

@app.route('/stream') # Streaming endpoint
def stream():
    """Creates an SSE stream for updates."""
    user_id = request.args.get('user_id')

    if not user_id:
        return "User ID required", 400
    if user_id not in users:
        # Initialize user data
        users[user_id] = {
            "message": read_html_file("defualt_blank.html",user_id),
            "lastmessage": "",  # Last loaded HTML (SHA-256 hash)
            "name": f"",  # Character name
            "location": "home",  # Store location from URL
            "joined": True
        }
    else:
        #reset when joined back
        users[user_id]["joined"] = True
        users[user_id]["lastmessage"] = ""
    
    return Response(generate(user_id), mimetype='text/event-stream')


def remove_html_tags(text: str) -> str:
    """
    Naive approach to remove HTML tags from a string.
    """
    # This regex finds anything from '<' to the next '>'
    cleaned_text = re.sub(r'<[^>]*>', '', text)
    return cleaned_text


def update_based_location(user_id):
    #if users[user_id]['location'] == "home":
    #    return read_html_file("test.html",user_id)
    #if users[user_id]['location'] == "diceroll":
    #    return read_html_file("dice.html",user_id)
    #if users[user_id]['location'] == "game":
    #    return read_html_file("game.html",user_id)
    return read_html_file("defualt_blank.html",user_id)

def update_users():
    """Updates the user's message and notifies the stream."""
    save_dict_pickle(users,'users.pkl')
    with update_event:
        update_event.notify_all()  # Wake up all waiting threads

def save_dict_pickle(data_dict, filename):
    """
    Saves a dictionary to a file in pickle format.
    """
    with open(filename, 'wb') as file:
        pickle.dump(data_dict, file)

def load_dict_pickle(filename):
    """
    Loads a dictionary from a pickle file.
    """
    with open(filename, 'rb') as file:
        data_dict = pickle.load(file)
    return data_dict


def b64_to_int_list(b64_str):
    return list(base64.b64decode(b64_str))

@app.route('/process', methods=['POST'])
def process():
    data = request.json
    user_id = data.get('user_id')
    input_type_b64 = data.get('type')
    value_b64 = data.get('value')

    aes = AES_SYSTEM(user_id[:32], 256)
    aes.load()

    try:
        input_type_bytes = b64_to_int_list(input_type_b64)
        value_bytes = b64_to_int_list(value_b64)

        decrypted_type = aes.decrypt(input_type_bytes)
        decrypted_value = aes.decrypt(value_bytes)
    except Exception as e:
        print(f"Decryption error: {e}")
        return jsonify({'error': 'Decryption failed'}), 400
    print(f"Decrypted type: {decrypted_type}, value: {decrypted_value}")
    if decrypted_type == 'keyup':
        users[user_id]["message"] = read_html_file("test1.html",user_id)
        update_users()

    elif decrypted_type == 'keydown':
        users[user_id]["message"] = read_html_file("test2.html",user_id)
        update_users()
        
    elif decrypted_type == 'name': # Update Users Name
        users[user_id]["name"] = remove_html_tags(f"{decrypted_value}")
        users[user_id]["message"] = update_based_location(user_id)
        update_users()
    elif decrypted_type == 'move': # Change Application Location
        users[user_id]['location'] = decrypted_value
        users[user_id]["message"] = update_based_location(user_id)
        update_users()
    elif decrypted_type == "sendmsg":
        users[user_id]["message"] = update_based_location(user_id)
    
    return jsonify({'status': 'success'}), 200


if os.path.isfile('users.pkl'):
    users = load_dict_pickle('users.pkl')
    print("Loaded dictionary")
else:
    users = {}



if __name__ == '__main__':
    # Initialize RSA system
    RSA = RSA_SYSTEM(4096)
    ensure_public_keys() # Ensure public keys are available
    app.run(debug=False, threaded=True, host='0.0.0.0', port=5421)