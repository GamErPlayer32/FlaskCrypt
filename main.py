# main.py

from flask import Flask, render_template, Response, request, jsonify
import time, threading, re, hashlib, random, datetime, pickle, os, base64, hmac, math, logging, html, json
from encrypt import RSA_SYSTEM, AES_SYSTEM
import shutil
import base64

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
    data = request.get_json() # Get JSON data from the request
    if not data or 'encrypted_key' not in data:
        return jsonify({'error': 'Invalid request'}), 400
    # Process the encrypted key
    aes_key_bytes = RSA.rsa_decryption(int(data['encrypted_key'], 16))

    aes_iv = RSA.rsa_decryption(int(data.get('iv', ''),16))
    aes_size = data.get('key_size',256)
    aes_sbox = RSA.rsa_decryption(int(data.get('sbox', ''), 16))
    timestamp = data.get('metadata',[]).get('timestamp', '')
    userID = data.get('metadata',[]).get('id', None)
    if not userID:
        return jsonify({'error': 'Missing required fields'}), 400
    if isinstance(aes_key_bytes, str):
        aes_key_bytes = aes_key_bytes.encode('latin1')  # fallback
    key_array = list(aes_key_bytes)
    iv_array = [int(aes_iv[i:i+2], 16) for i in range(0, len(aes_iv), 2)]
    print("Decrypted key:", key_array)
    if isinstance(aes_sbox, bytes):
        aes_sbox = aes_sbox.decode('utf-8')

    if len(aes_sbox) != 512:
        raise ValueError(f"SBOX is not the correct length: {len(aes_sbox)}")

    sbox_list = [int(aes_sbox[i:i+2], 16) for i in range(0, 512, 2)]
    sbox = {i: sbox_list[i] for i in range(256)}
    inv_sbox = {v: k for k, v in sbox.items()}
    
    users[userID]["aes"] = AES_SYSTEM(userID[:32], aes_size)
    users[userID]["aes"].key = key_array  # not aes_key
    users[userID]["aes"].iv = iv_array    # not aes_iv
    users[userID]["aes"].sbox = sbox
    users[userID]["aes"].inv_sbox = inv_sbox
    users[userID]["aes"].round_keys = users[userID]["aes"]._expand_key(key_array)
    users[userID]["aes"].save()
    print(f"Received: {key_array} {iv_array} {timestamp}")
    response = {'reply': f"AES KEY CONFIRMED: Timestamp: {timestamp}"}
    return jsonify(response)

def read_html_file(file_path,user_id):
    try:
        with open("blobs/"+file_path, 'r', encoding='utf-8') as file:
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

    print(f"Processing: {input_type_b64} {value_b64}")
    
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

    print(f"Decrypted: {decrypted_type} {decrypted_value}")
    
    if decrypted_type == 'keyup':
        users[user_id]["message"] = update_based_location(user_id)
    elif decrypted_type == 'keydown':
        users[user_id]["message"] = update_based_location(user_id)
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
       
    else:
        users[user_id]["message"] = read_html_file("default_blank.html",user_id)
        update_users()
    
    
    return "update"


if os.path.isfile('users.pkl'):
    users = load_dict_pickle('users.pkl')
    print("Loaded dictionary")
else:
    users = {}


if __name__ == '__main__':
    RSA = RSA_SYSTEM(4096)
    ensure_public_keys() # Ensure public keys are available
    app.run(debug=True, threaded=True, host='0.0.0.0', port=5421)