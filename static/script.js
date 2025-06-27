// Output "Hello, World!" to the console

// Function to load RSA exponent and modulus from files
/**
 * Loads the RSA public exponent from a file.
 * @returns {Promise<BigInt>} - The RSA public exponent as a BigInt.
 */
async function loadRSA(filePath = '/static/rsa_e.key') {
  const response = await fetch(filePath);
  const hexString = await response.text();
  return BigInt('0x' + hexString.trim());
}

function generateUserId(bytes = 256) {
    const array = new Uint8Array(bytes);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

function rsa_encrypt_bytes(bytes, e, n) {
    const msgBigInt = BigInt('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
    const encryptedBigInt = modPow(msgBigInt, e, n);
    return encryptedBigInt.toString(16); // send as hex
}

// Main function to load RSA keys and perform encryption
async function main() {
    const [rsaExponent, rsaModulus] = await Promise.all([
      loadRSA('/static/rsa_e.key'),
      loadRSA('/static/rsa_n.key'),
    ])
    const storedId = localStorage.getItem("userId");
    const userId = storedId || (() => {
        const newId = generateUserId();
        localStorage.setItem("userId", newId);
        return newId;
    })();
    
    const aesSystem = new AESSystem(userId, 256); // Default to 128 bits
    // Generate a new key if not already set
    if (!localStorage.getItem(`aes_${userId}_key`)) {
        aesSystem.generate();
    }

    // Now use rsaExponent safely
    const sboxHex = Object.values(aesSystem.sbox)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    const keyBytes = Uint8Array.from(aesSystem.key);
    const ivHex = aesSystem.iv
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
    const encryptedSbox = rsa_encrypt(sboxHex, rsaExponent, rsaModulus);
    const encryptedKey = rsa_encrypt_bytes(keyBytes, rsaExponent, rsaModulus);
    const encryptedIV = rsa_encrypt(ivHex, rsaExponent, rsaModulus)
    sendMessageToFlask('/api/security', null, {
        encrypted_key: encryptedKey,
        iv: encryptedIV,
        key_size: aesSystem.keyBits,
        sbox: encryptedSbox,
        metadata: { 
          id: userId, 
          timestamp: Date.now() 
        }
    });
    
    // Start listening for streaming updates
    startListening(userId)
}

//// Function to perform modular exponentiation
/**
 * Performs modular exponentiation using the method of exponentiation by squaring.
 * @param {BigInt} base - The base number.
 * @param {BigInt} exponent - The exponent.
 * @param {BigInt} modulus - The modulus.
 * @returns {BigInt} - The result of (base^exponent) mod modulus.
 */
function modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2n === 1n) {
            result = (result * base) % modulus;
        }
        exponent = exponent >> 1n; // Divide by 2
        base = (base * base) % modulus;
    }
    return result;
}


//// RSA encryption function
/**
 * Encrypts a message using RSA encryption.
 * @param {string} msg - The message to encrypt.
 * @param {BigInt} e - The RSA public exponent.
 * @param {BigInt} n - The RSA modulus.
 * @returns {string} - The encrypted message as a hex string.
 */
function rsa_encrypt(msg, e, n) {
    // Convert message to Uint8Array and then to hex string
    const encoder = new TextEncoder();
    const msgBytes = encoder.encode(msg);
    const hex = Array.from(msgBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const msgBigInt = BigInt('0x' + hex);

    // Encrypt using RSA: c = m^e mod n
    const encryptedBigInt = modPow(msgBigInt, e, n);

    // Convert encrypted BigInt back to hex string
    const encryptedHex = encryptedBigInt.toString(16);

    return encryptedHex;
}

// Function to send a message to the Flask backend
/**
 * Sends a message to the Flask backend and logs the response.
 * @param {string} heading - The heading for the message.
 * @param {string} message - The message to send.
 */
function sendMessageToFlask(api, heading, message) {
    let payload;

    if (typeof message === 'object' && message !== null) {
        payload = message;  // already an object with multiple fields
    } else {
        payload = {};
        payload[heading] = message;  // single key-value pair
    }

    fetch(api, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json; charset=utf-8'
        },
        body: JSON.stringify(payload)
    })
    .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
    })
    .then(data => {
        console.log('Response from Flask:', data.reply);
    })
    .catch(error => {
        console.error('Error:', error);
    });
}



//AES encryption function
class AESSystem {
    constructor(user, keyBits = 128) {
        if (![128, 192, 256].includes(keyBits)) {
            throw new Error("Key must be 128, 192, or 256 bits");
        }
        this.user = user;
        this.keyBits = keyBits;
        this.blockSize = 16;
        this.rounds = { 128: 10, 192: 12, 256: 14 }[keyBits];
        this.sbox = this._generateSBox();
        this.invSbox = Object.fromEntries(Object.entries(this.sbox).map(([k, v]) => [v, +k]));
        this.key = [];
        this.iv = [];
        this.roundKeys = [];
        this.savePath = `aes_${user}`;
        this.load();
    }

    generate() {
        this.key = Array.from({ length: this.keyBits / 8 }, () => Math.floor(Math.random() * 256));
        this.iv = Array.from({ length: this.blockSize }, () => Math.floor(Math.random() * 256));
        this.roundKeys = this._expandKey(this.key);
        this.save();
    }

    save() {
        const base = this.savePath;
        localStorage.setItem(`${base}_key`, this.key.join(','));
        localStorage.setItem(`${base}_iv`, this.iv.join(','));
        localStorage.setItem(`${base}_keysize`, this.keyBits.toString());
        localStorage.setItem(`${base}_sbox`, Array.from({ length: 256 }, (_, i) => this.sbox[i]).join(','));
    }

    load() {
        try {
            const base = this.savePath;
            this.key = localStorage.getItem(`${base}_key`).split(',').map(Number);
            this.iv = localStorage.getItem(`${base}_iv`).split(',').map(Number);
            this.keyBits = parseInt(localStorage.getItem(`${base}_keysize`));
            this.rounds = { 128: 10, 192: 12, 256: 14 }[this.keyBits];
            const sboxValues = localStorage.getItem(`${base}_sbox`).split(',').map(Number);
            this.sbox = Object.fromEntries(sboxValues.map((v, i) => [i, v]));
            this.invSbox = Object.fromEntries(sboxValues.map((v, i) => [v, i]));
            this.roundKeys = this._expandKey(this.key);
        } catch {
            this.generate();
        }
    }

    encrypt(plaintext) {
        const padded = this._pad(Array.from(plaintext).map(c => c.charCodeAt(0)));
        const blocks = [];
        for (let i = 0; i < padded.length; i += this.blockSize) {
            blocks.push(padded.slice(i, i + this.blockSize));
        }

        // ✅ Generate new random IV for this encryption
        const iv = Array.from({ length: this.blockSize }, () => Math.floor(Math.random() * 256));

        const encrypted = [];
        let prevBlock = [...iv];

        for (const block of blocks) {
            const xorBlock = block.map((b, i) => b ^ prevBlock[i]);
            const cipherBlock = this._encryptBlock(xorBlock);
            encrypted.push(...cipherBlock);
            prevBlock = cipherBlock;
        }

        return [...iv, ...encrypted]; // ✅ Prepend IV to the ciphertext
    }

    decrypt(ciphertext) {
        const iv = ciphertext.slice(0, this.blockSize);
        const encrypted = ciphertext.slice(this.blockSize);
        const blocks = [];
        for (let i = 0; i < encrypted.length; i += this.blockSize) {
            blocks.push(encrypted.slice(i, i + this.blockSize));
        }

        const decrypted = [];
        let prevBlock = iv;
        for (const block of blocks) {
            const plainBlock = this._decryptBlock(block);
            const xorBlock = plainBlock.map((b, i) => b ^ prevBlock[i]);
            decrypted.push(...xorBlock);
            prevBlock = block;
        }
        return String.fromCharCode(...this._unpad(decrypted));
    }

    // Internal AES-style functions
    _encryptBlock(block) {
        let state = [...block];
        for (let r = 0; r < this.rounds; r++) {
            state = this._subBytes(state);
            state = this._shiftRows(state);
            if (r !== this.rounds - 1) {
                state = this._mixColumns(state);
            }
            state = this._addRoundKey(state, this.roundKeys[r]);
        }
        return state;
    }

    _decryptBlock(block) {
        let state = [...block];
        for (let r = this.rounds - 1; r >= 0; r--) {
            state = this._addRoundKey(state, this.roundKeys[r]);
            if (r !== this.rounds - 1) {
                state = this._invMixColumns(state);
            }
            state = this._invShiftRows(state);
            state = this._invSubBytes(state);
        }
        return state;
    }

    _generateSBox() {
        const values = Array.from({ length: 256 }, (_, i) => i);
        for (let i = values.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [values[i], values[j]] = [values[j], values[i]];
        }
        return Object.fromEntries(values.map((v, i) => [i, v]));
    }

    _pad(block) {
        const padLen = this.blockSize - (block.length % this.blockSize);
        return block.concat(Array(padLen).fill(padLen));
    }

    _unpad(block) {
        const padLen = block[block.length - 1];
        return block.slice(0, -padLen);
    }

    _subBytes(block) {
        return block.map(b => this.sbox[b]);
    }

    _invSubBytes(block) {
        return block.map(b => this.invSbox[b]);
    }

    _shiftRows(block) {
        const b = [...block];
        for (let r = 1; r < 4; r++) {
            const row = b.slice(r, 16).filter((_, i) => i % 4 === 0);
            const rotated = row.slice(r).concat(row.slice(0, r));
            for (let i = 0; i < rotated.length; i++) {
                b[r + i * 4] = rotated[i];
            }
        }
        return b;
    }

    _invShiftRows(block) {
        const b = [...block];
        for (let r = 1; r < 4; r++) {
            const row = b.slice(r, 16).filter((_, i) => i % 4 === 0);
            const rotated = row.slice(-r).concat(row.slice(0, -r));
            for (let i = 0; i < rotated.length; i++) {
                b[r + i * 4] = rotated[i];
            }
        }
        return b;
    }

    _mixColumns(block) {
        const b = [...block];
        for (let i = 0; i < b.length; i += 4) {
            [b[i], b[i + 1], b[i + 2], b[i + 3]] = [b[i + 1], b[i + 2], b[i + 3], b[i]];
        }
        return b;
    }

    _invMixColumns(block) {
        const b = [...block];
        for (let i = 0; i < b.length; i += 4) {
            [b[i], b[i + 1], b[i + 2], b[i + 3]] = [b[i + 3], b[i], b[i + 1], b[i + 2]];
        }
        return b;
    }

    _addRoundKey(block, key) {
        return block.map((b, i) => b ^ key[i]);
    }

    _expandKey(key) {
        const keys = [];
        const keyLen = key.length;
        for (let r = 0; r < this.rounds; r++) {
            const rotated = key.slice(r % keyLen).concat(key.slice(0, r % keyLen));
            keys.push(rotated.slice(0, this.blockSize));
        }
        return keys;
    }
}







//STREAMING
function startListening(userId = localStorage.getItem("userId")) {
  const eventSource = new EventSource(`/stream?user_id=${userId}`);

  eventSource.onmessage = function(event) {
      const newData = event.data;

      // Store input values and selection position before update
      const inputs = document.querySelectorAll("input, textarea");
      let inputData = {};
      let lastFocusedId = document.activeElement?.id || null;
      let cursorPosition = document.activeElement?.selectionStart || 0;

      inputs.forEach(input => {
          inputData[input.id] = {
              value: input.value,
              selectionStart: input.selectionStart,
              selectionEnd: input.selectionEnd
          };
      });


      // Update only the content, not input fields
      const outputDiv = document.getElementById('output');
      outputDiv.innerHTML = `
          <div style="border: 2px solid black; padding: 10px; margin-top: 10px; background-color: #ffffff !important;">
              ${newData}
          </div>
      `;

      // Restore input values and cursor positions
      Object.keys(inputData).forEach(id => {
          let inputField = document.getElementById(id);
          if (inputField) {
              inputField.value = inputData[id].value;
              inputField.selectionStart = inputData[id].selectionStart;
              inputField.selectionEnd = inputData[id].selectionEnd;
          }
      });

      // Restore focus to the last selected input field
      if (lastFocusedId) {
          let focusedElement = document.getElementById(lastFocusedId);
          if (focusedElement) {
              focusedElement.focus();
              focusedElement.setSelectionRange(cursorPosition, cursorPosition);
          }
      }
  };

  eventSource.onerror = function() {
      console.log("Connection lost, attempting to reconnect...");
      eventSource.close();
      setTimeout(startListening(userId), 3000);
  };
}

function sendInput(type, value, userId = localStorage.getItem("userId")) {
  const system = new AESSystem(userId);
  system.load();

  if (!userId) {
      console.error("User ID not found. Please generate or set a user ID.");
      return;
  }

  // Convert encrypted arrays to base64 strings
  const encryptedType = btoa(system.encrypt(type).map(b => String.fromCharCode(b)).join(''));
  const encryptedValue = btoa(system.encrypt(value).map(b => String.fromCharCode(b)).join(''));

  fetch('/process', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
          user_id: userId, 
          type: encryptedType, 
          value: encryptedValue 
      })
  });
}


// Listen for certain keys only when NOT focused in an input/textarea
const allowedKeys = new Set([
  // Arrow keys
  'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight',
  // Digits 0-9
  '0','1','2','3','4','5','6','7','8','9'
]);

// Add a-z
for (let code = 97; code <= 122; code++) {
  allowedKeys.add(String.fromCharCode(code));
}

// Listen for keydown
document.addEventListener("keydown", (event) => {
  // If focus is on an input or textarea, ignore
  const activeTag = document.activeElement.tagName.toLowerCase();
  if (activeTag === "input" || activeTag === "textarea") return;

  if (allowedKeys.has(event.key)) {
      sendInput("keydown", event.key);
  }
});

// Listen for keyup
document.addEventListener("keyup", (event) => {
  // If focus is on an input or textarea, ignore
  const activeTag = document.activeElement.tagName.toLowerCase();
  if (activeTag === "input" || activeTag === "textarea") return;

  if (allowedKeys.has(event.key)) {
      sendInput("keyup", event.key);
  }
});





























// Check if the DOM is ready
if (document.readyState === 'loading') {
  // Wait until DOM is ready
  document.addEventListener('DOMContentLoaded', main);
} else {
  // DOM already ready
  main();
}