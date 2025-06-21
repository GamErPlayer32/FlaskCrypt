import random
import math
import multiprocessing
from multiprocessing import Process, Queue, Event, cpu_count, Pool
import time
import os

def is_prime(n, k=5):
    if n <= 3:
        return n == 2 or n == 3
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def prime_worker(bit_length, found_event, result_queue):
    while not found_event.is_set():
        p = random.getrandbits(bit_length) | (1 << bit_length - 1) | 1
        if is_prime(p):
            if not found_event.is_set():
                result_queue.put(p)
                found_event.set()
            break

def generate_large_prime_parallel(bit_length, num_workers=cpu_count()):
    manager = multiprocessing.Manager()
    found_event = manager.Event()
    result_queue = manager.Queue()

    workers = [
        Process(target=prime_worker, args=(bit_length, found_event, result_queue))
        for _ in range(num_workers)
    ]

    for w in workers:
        w.start()

    prime = result_queue.get()  # Blocks until one result is available
    found_event.set()  # Signal all workers to stop

    for w in workers:
        w.terminate()
        w.join()

    return prime

LIMIT = 10000  # Max coprimes per process

def find_coprimes_worker(start, end, phi_n, result_queue):
    
    found = []
    for e in range(start, end):
        if math.gcd(e, phi_n) == 1:
            found.append(e)
            if len(found) >= LIMIT:
                break
    result_queue.put(found)

def find_coprimes_phi(phi_n):
    num_cpus = cpu_count()
    step = (phi_n - 2) // num_cpus
    processes = []
    result_queue = Queue()

    for i in range(num_cpus):
        start = 2 + i * step
        end = 2 + (i + 1) * step if i < num_cpus - 1 else phi_n
        p = Process(target=find_coprimes_worker, args=(start, end, phi_n, result_queue))
        processes.append(p)
        p.start()

    all_results = []
    for _ in processes:
        all_results.extend(result_queue.get())

    for p in processes:
        p.join()

    if not all_results:
        raise ValueError("No coprimes found.")
    
    return random.choice(all_results)

class RSA_SYSTEM():
    def __init__(self, bit_length=4096):
        self.rsa_n = 0
        self.rsa_d = 0
        self.rsa_e = 0
        self.bit_length = bit_length
        self.load()

    def generate(self):
        start_time = time.time()
        half_bits = self.bit_length // 2
        while True:
            rsa_prime_p = generate_large_prime_parallel(half_bits)
            rsa_prime_q = generate_large_prime_parallel(half_bits)
            n = rsa_prime_p * rsa_prime_q
            if n.bit_length() >= self.bit_length:
                break
        self.rsa_n = n
        rsa_phi_n = (rsa_prime_p-1)*(rsa_prime_q-1)

        
        self.rsa_e = find_coprimes_phi(rsa_phi_n) # 1 < e < phi_n and coprime with n and phi_n
        print("found RSA_E")
        def modinv(e, phi_n):
            t, newt = 0, 1
            r, newr = phi_n, e
            while newr != 0:
                q = r // newr
                t, newt = newt, t - q * newt
                r, newr = newr, r - q * newr
            if r != 1:
                raise Exception("No modular inverse")
            return t + phi_n if t < 0 else t

        self.rsa_d = modinv(self.rsa_e, rsa_phi_n)
        print(f"Done {time.time()-start_time}s")

        self.save()

    def save(self):
        with open("saves/private/rsa_d.key", "w") as file:
            file.write(f"{hex(self.rsa_d)[2:]}")
        with open("saves/public/rsa_e.key", "w") as file:
            file.write(f"{hex(self.rsa_e)[2:]}")
        with open("saves/public/rsa_n.key", "w") as file:
            file.write(f"{hex(self.rsa_n)[2:]}")

    
    def load(self):
        if not (os.path.exists("saves/private/rsa_d.key") and
                os.path.exists("saves/public/rsa_e.key") and
                os.path.exists("saves/public/rsa_n.key")):
            self.generate()
        else:
            with open("saves/private/rsa_d.key", "r") as file:
                self.rsa_d = int(file.read(), 16)
            with open("saves/public/rsa_e.key", "r") as file:
                self.rsa_e = int(file.read(), 16)
            with open("saves/public/rsa_n.key", "r") as file:
                self.rsa_n = int(file.read(), 16)


    def rsa_encrypt(self, msg: str | bytes) -> int:
        if isinstance(msg, str):
            msg = msg.encode('utf-8')  # Convert string to bytes

        text_int = int.from_bytes(msg, byteorder='big')
        cipher_int = pow(text_int, self.rsa_e, self.rsa_n)
        return cipher_int
    
    def rsa_decryption(self, cipher_int: int) -> str | bytes:
        decrypted_int = pow(cipher_int, self.rsa_d, self.rsa_n)
        decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')
        try:
            return decrypted_bytes.decode('utf-8')  # Try decoding if it's valid text
        except UnicodeDecodeError:
            return decrypted_bytes  # Fallback to raw bytes
    
    def decrypt(self, ciphertext: int) -> int:
        # Standard RSA decryption: m = c^d mod n
        return pow(ciphertext, self.rsa_d, self.rsa_n)

import random
import math

class AES_SYSTEM:
    def __init__(self, user, key_bits=128):
        assert key_bits in [128, 192, 256], "Key must be 128, 192, or 256 bits"
        self.user = user
        self.key_bits = key_bits
        self.block_size = 16
        self.rounds = {128: 10, 192: 12, 256: 14}[key_bits]
        self.sbox = self._generate_sbox()
        self.inv_sbox = {v: k for k, v in self.sbox.items()}
        self.key = []
        self.iv = []
        self.round_keys = []
        self.save_path = f"saves/users/{self.user}/aes"
        os.makedirs(self.save_path, exist_ok=True)
        self.load()

    def generate(self):
        self.key = [random.randint(0, 255) for _ in range(self.key_bits // 8)]
        self.iv = [random.randint(0, 255) for _ in range(self.block_size)]
        self.round_keys = self._expand_key(self.key)
        self.save()

    def save(self):
        with open(f"{self.save_path}/key.key", "w") as f:
            f.write(','.join(map(str, self.key)))
        with open(f"{self.save_path}/iv.key", "w") as f:
            f.write(','.join(map(str, self.iv)))
        with open(f"{self.save_path}/keysize.key", "w") as f:
            f.write(str(self.key_bits))
        with open(f"{self.save_path}/sbox.key", "w") as f:
            f.write(','.join(str(self.sbox[i]) for i in range(256)))

    def load(self):
        try:
            with open(f"{self.save_path}/key.key", "r") as f:
                self.key = list(map(int, f.read().strip().split(',')))
            with open(f"{self.save_path}/iv.key", "r") as f:
                self.iv = list(map(int, f.read().strip().split(',')))
            with open(f"{self.save_path}/keysize.key", "r") as f:
                self.key_bits = int(f.read().strip())
                self.rounds = {128: 10, 192: 12, 256: 14}[self.key_bits]
            with open(f"{self.save_path}/sbox.key", "r") as f:
                values = list(map(int, f.read().strip().split(',')))
                self.sbox = {i: values[i] for i in range(256)}
                self.inv_sbox = {v: k for k, v in self.sbox.items()}
            self.round_keys = self._expand_key(self.key)
        except Exception:
            self.generate()

    def encrypt(self, plaintext):
        padded = self._pad([ord(c) for c in plaintext])
        blocks = [padded[i:i+self.block_size] for i in range(0, len(padded), self.block_size)]

        encrypted = []
        prev_block = self.iv[:]
        for block in blocks:
            xor_block = [b ^ p for b, p in zip(block, prev_block)]
            cipher_block = self._encrypt_block(xor_block)
            encrypted.extend(cipher_block)
            prev_block = cipher_block
        return self.iv + encrypted

    def decrypt(self, ciphertext):
        iv = ciphertext[:self.block_size]
        encrypted = ciphertext[self.block_size:]
        blocks = [encrypted[i:i+self.block_size] for i in range(0, len(encrypted), self.block_size)]
        decrypted = []
        prev_block = iv
        for block in blocks:
            plain_block = self._decrypt_block(block)
            xor_block = [b ^ p for b, p in zip(plain_block, prev_block)]
            decrypted.extend(xor_block)
            prev_block = block
        try:
            result = ''.join(chr(b) for b in self._unpad(decrypted))
            return result
        except Exception as e:
            return ""


    # ===== Internal AES-like operations below =====

    def _encrypt_block(self, block):
        state = block[:]
        for r in range(self.rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            if r != self.rounds - 1:
                state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[r])
        return state

    def _decrypt_block(self, block):
        state = block[:]
        for r in reversed(range(self.rounds)):
            state = self._add_round_key(state, self.round_keys[r])
            if r != self.rounds - 1:
                state = self._inv_mix_columns(state)
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
        return state

    def _generate_sbox(self):
        values = list(range(256))
        random.shuffle(values)
        return {i: values[i] for i in range(256)}

    def _pad(self, block):
        pad_len = self.block_size - len(block) % self.block_size
        return block + [pad_len] * pad_len

    def _unpad(self, block):
        pad_len = block[-1]
        return block[:-pad_len]

    def _sub_bytes(self, block):
        return [self.sbox[b] for b in block]

    def _inv_sub_bytes(self, block):
        return [self.inv_sbox[b] for b in block]

    def _shift_rows(self, block):
        b = block[:]
        for r in range(1, 4):
            b[r::4] = b[r::4][r:] + b[r::4][:r]
        return b

    def _inv_shift_rows(self, block):
        b = block[:]
        for r in range(1, 4):
            b[r::4] = b[r::4][-r:] + b[r::4][:-r]
        return b

    def _mix_columns(self, block):
        b = block[:]
        for i in range(0, len(b), 4):
            b[i:i+4] = b[i+1:i+4] + [b[i]]
        return b

    def _inv_mix_columns(self, block):
        b = block[:]
        for i in range(0, len(b), 4):
            b[i:i+4] = [b[i+3]] + b[i:i+3]
        return b

    def _add_round_key(self, block, key):
        return [b ^ k for b, k in zip(block, key)]

    def _expand_key(self, key):
        keys = []
        key_len = len(key)
        for r in range(self.rounds):
            rotated = key[r % key_len:] + key[:r % key_len]
            keys.append(rotated[:self.block_size])
        return keys

if __name__ == '__main__':
    #EXAMPLE TEST CODE only runs during test
    RSA_SYSTEM(4096)
