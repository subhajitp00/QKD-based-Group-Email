import numpy as np
from flask import Flask, request, jsonify
from qiskit import QuantumCircuit
from qiskit_aer import Aer
import hashlib
import math
import random
import logging
import sqlite3
import uuid
import datetime
import os
import time
import keygen
import traceback
from dilithium_py.dilithium import Dilithium2
from threading import Lock

# --- Basic Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
BACKEND = Aer.get_backend("qasm_simulator")

# --- Server and Security Configuration ---
SERVER_NAME = "alice_server"
PRIV_KEY_FILE = f"{SERVER_NAME}_dilithium.key"
PUB_KEY_FILE = f"{SERVER_NAME}_dilithium.pub"
SECURITY_DB_FILE = "security.db"
desired_key_length, kdf_size = 1024, 32

# --- PQC Digital Signature (Unchanged) ---
def sign_message(msg):
    with open(PRIV_KEY_FILE, "rb") as f:
        private_key = f.read()
    return Dilithium2.sign(private_key, msg)

# --- SQLite Database for Final Keys (Unchanged) ---
conference_db_conn = sqlite3.connect('conference_keys.db', check_same_thread=False)
conference_cursor = conference_db_conn.cursor()
conference_cursor.execute('''
CREATE TABLE IF NOT EXISTS conference_keys (
    uuid TEXT PRIMARY KEY, conference_key TEXT NOT NULL, indices TEXT NOT NULL,
    key_length TEXT NOT NULL, key_generated_at TEXT NOT NULL, expires_at TEXT NOT NULL
)''')
conference_db_conn.commit()

# --- Allowlist Helper (Unchanged) ---
def get_public_key_from_allowlist(party_name):
    if not os.path.exists(SECURITY_DB_FILE): return None
    with sqlite3.connect(SECURITY_DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT public_key_hex FROM allowlist WHERE party_name = ? AND status = 'active'", (party_name,))
        row = cursor.fetchone()
        return bytes.fromhex(row[0]) if row else None

# --- Cryptographic Helpers (Unchanged) ---
def generate_random_nonce(length=16):
    return ''.join(random.choice('01') for _ in range(length))
def KDF(input_str, length=32):
    hash_val = hashlib.sha256(input_str.encode()).hexdigest()
    return bin(int(hash_val, 16))[2:].zfill(256)[:length]
def extend_key(sifted_key_bin, nonce, required_length, kdf_size):
    num_blocks = math.ceil(required_length / kdf_size)
    blocks = [f"p{i+1}" for i in range(num_blocks)]
    extended = ""
    for b in blocks:
        extended += KDF(sifted_key_bin + nonce + b, length=kdf_size)
    return extended[:required_length]
def find_consensus_indices(extended_keys):
    if not extended_keys: return [], ""
    min_len = min(len(k) for k in extended_keys.values())
    indices, consensus_bits = [], []
    for i in range(min_len):
        bits = [key[i] for key in extended_keys.values()]
        if all(bit == bits[0] for bit in bits):
            indices.append(i)
            consensus_bits.append(bits[0])
    return indices, ''.join(consensus_bits)

# --- BB84Party Class ---
class BB84Party:
    def __init__(self, n_bits=29):
        # MODIFIED: Added poll_count to track /sift requests for this party.
        self.n_bits, self.name, self.bits, self.bases, self.circuits, self.sifted_key, self.extended_key, self.authenticated, self.challenge, self.poll_count = n_bits, None, None, None, None, None, None, False, None, 0
    def prepare(self):
        self.bits = np.random.randint(2, size=self.n_bits)
        self.bases = np.random.randint(2, size=self.n_bits)
        self.circuits = [self._encode_bit(b, bas) for b, bas in zip(self.bits, self.bases)]
    def _encode_bit(self, bit, basis):
        qc = QuantumCircuit(1, 1);
        if bit: qc.x(0)
        if basis: qc.h(0)
        return qc
    def serialize_circuits(self):
        return [[inst.operation.name for inst in qc.data] for qc in self.circuits]
    def sift(self, party_bases, party_results):
        p_bases, p_results = np.array(party_bases), np.array(party_results)
        mask = (p_bases == self.bases)
        self.sifted_key = self.bits[mask]
    def extend(self, nonce, required_length, kdf_size):
        if self.sifted_key is not None and len(self.sifted_key) > 0:
            key_bin = ''.join(str(b) for b in self.sifted_key)
            self.extended_key = extend_key(key_bin, nonce, required_length, kdf_size)

# --- Performance Logging Helper (Unchanged) ---
def log_performance(filename, headers, data_row):
    if not os.path.exists(filename):
        with open(filename, "w") as f: f.write(headers + "\n")
    with open(filename, "a") as f: f.write(data_row + "\n")

# --- Flask App and Multithreaded State Management ---
app = Flask(__name__)
session_lock = Lock()
parties = {}
nonce = None
session_key_gen_start_time = None
session_result = None
pending_sessions = {}

# --- API Endpoints ---
@app.route('/prove_identity', methods=['POST'])
def prove_identity():
    challenge = request.json['challenge']
    signature = sign_message(challenge.encode())
    return jsonify({'signature': signature.hex()})

@app.route('/start/<party>', methods=['POST'])
def start(party):
    global nonce, session_key_gen_start_time, session_result
    with session_lock:
        if nonce is None: #or session_result is not None:
            parties.clear()
            session_result = None
            nonce = generate_random_nonce()
            session_key_gen_start_time = time.time()
            logging.info("--- TRULY PARALLEL SESSION STARTED: Timer initiated. ---")
    p = BB84Party()
    p.name = party
    p.prepare()
    p.challenge = generate_random_nonce(32)
    with session_lock:
        parties[party] = p
        return jsonify({'nonce': nonce, 'n_bits': p.n_bits, 'pqc_challenge': p.challenge, 'desired_key_length': desired_key_length, 'kdf_size': kdf_size})

@app.route('/authenticate', methods=['POST'])
def authenticate():
    party_name = request.json['party_name']
    signature_hex = request.json['signature']
    with session_lock:
        p = parties.get(party_name)
    if not p:
        return jsonify({'error': 'Party not found'}), 404
    public_key = get_public_key_from_allowlist(party_name)
    if not public_key:
        return jsonify({'status': 'authentication_failed_not_in_allowlist'}), 403
    is_valid = Dilithium2.verify(public_key, p.challenge.encode(), bytes.fromhex(signature_hex))
    if is_valid:
        with session_lock:
            p.authenticated = True
        return jsonify({'status': 'authenticated'})
    else:
        return jsonify({'status': 'authentication_failed_invalid_signature'}), 401

@app.route('/qubits/<party>', methods=['GET'])
def qubits(party):
    with session_lock:
        p = parties.get(party)
        if not p or not p.authenticated:
            return jsonify({'error': 'Party not authenticated'}), 403
        circuits = p.serialize_circuits()
    return jsonify({'circuits': circuits})

@app.route('/bases/<party>', methods=['GET'])
def bases(party):
    with session_lock:
        p = parties.get(party)
        if not p or not p.authenticated:
            return jsonify({'error': 'Party not authenticated'}), 403
        bases_list = p.bases.tolist()
    return jsonify({'bases': bases_list})

@app.route('/sift/<party>', methods=['POST'])
def sift(party):
    global session_result
    with session_lock:
        p = parties.get(party)
        current_nonce = nonce

    if not p or not p.authenticated:
        return jsonify({'error': 'Party not authenticated'}), 403
    
    # MODIFIED: Increment this party's poll counter.
    p.poll_count += 1
    
    p.sift(request.json.get('bases'), request.json.get('results'))
    p.extend(current_nonce, desired_key_length, kdf_size)

    with session_lock:
        try:
            if session_result:
                return jsonify(session_result)

            total_auth_clients = len([p for p in parties.values() if p.authenticated])
            finished_clients = {name: p for name, p in parties.items() if p.authenticated and p.extended_key is not None}

            if total_auth_clients > 1 and len(finished_clients) == total_auth_clients:
                logging.info("Consensus reached in true parallel mode.")
                
                duration = time.time() - session_key_gen_start_time
                # MODIFIED: Sum the poll counts from all finished clients.
                total_polls = sum(p.poll_count for p in finished_clients.values())
                
                # MODIFIED: Log the total polls to a new CSV file.
                '''log_performance("key_gen_times_parallel_with_polls.csv", "timestamp,num_clients,key_generation_time_seconds,total_polls",
                                f"{datetime.datetime.now().isoformat()},{len(finished_clients)},{duration},{total_polls}")'''

                extended_keys = {name: p.extended_key for name, p in finished_clients.items()}
                consensus_indices, conf_key = find_consensus_indices(extended_keys)
                
                '''conference_cursor.execute('SELECT uuid, key_generated_at, expires_at FROM conference_keys WHERE conference_key = ?', (conf_key,))
                row = conference_cursor.fetchone()
                if row:
                    conf_key_uuid, ts, expires_at = row
                else:
                    conf_key_uuid = str(uuid.uuid4())
                    now = datetime.datetime.now(datetime.timezone.utc)
                    ts = now.isoformat()
                    expires_at = (now + datetime.timedelta(hours=24)).isoformat()
                    conference_cursor.execute(
                        'INSERT INTO conference_keys (uuid, conference_key, indices, key_length, key_generated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
                        (conf_key_uuid, conf_key, ','.join(map(str, consensus_indices)), len(conf_key), ts, expires_at)
                    )
                    conference_db_conn.commit()

                session_result = {
                    'status': 'consensus_reached', 
                    'conference_key_indices': consensus_indices,
                    'conference_key_length': len(conf_key),
                    'conference_key_uuid': conf_key_uuid,
                    'expires_at': expires_at, 
                    'key_generated_at': ts
                }
                
                return jsonify(session_result)'''
                # prepare the data and store it in the pending dictionary.
                conf_key_uuid = str(uuid.uuid4())
                now = datetime.datetime.now(datetime.timezone.utc)
                ts = now.isoformat()
                expires_at = (now + datetime.timedelta(hours=24)).isoformat()

                pending_sessions[conf_key_uuid] = {
                    "key_data": {
                        "uuid": conf_key_uuid,
                        "conference_key": conf_key,
                        "indices": ','.join(map(str, consensus_indices)),
                        "key_length": len(conf_key),
                        "key_generated_at": ts,
                        "expires_at": expires_at
                    },
                    "participants": list(finished_clients.keys()),
                    "confirmed": [],  # An empty list to track confirmations
                    "confirmation_start_time": time.time(),  # Start the confirmation timer
                    "metrics": {  # NEW: Store metrics here
                        "key_generation_duration": duration,
                        "total_polls": total_polls,
                        "num_clients": len(finished_clients)
                }
                }
                
                # The session_result now just contains the metadata for the client
                session_result = {
                    'status': 'consensus_reached', 
                    'conference_key_indices': consensus_indices,
                    'conference_key_length': len(conf_key),
                    'conference_key_uuid': conf_key_uuid, # Send the new UUID
                    'expires_at': expires_at, 
                    'key_generated_at': ts
                }
                # --- START THE TIMER HERE FOR CONFIRMATION PHASE TIMER ---

                pending_sessions[conf_key_uuid]['confirmation_start_time'] = time.time()
            
                return jsonify(session_result)
            else:
                return jsonify({'status': 'waiting_for_parties'})
                
        except Exception as e:
            logging.error(f"!!! Unhandled error in /sift for party '{party}': {e} !!!")
            traceback.print_exc()
            return jsonify({'error': 'An internal server error occurred.', 'details': str(e)}), 500
# Add this new endpoint to your server script

@app.route('/confirm_storage', methods=['POST'])
def confirm_storage():
    global start_time, nonce, session_result
    with session_lock: # Or sequential_lock
        data = request.json
        key_uuid = data.get('uuid')
        party_name = data.get('party_name')

        if not key_uuid or not party_name:
            return jsonify({'status': 'error', 'message': 'Missing UUID or party name'}), 400

        pending_session = pending_sessions.get(key_uuid)
        if not pending_session:
            # This can happen if another client already confirmed and the session was committed
            logging.warning(f"Confirmation received for already committed or unknown session UUID: {key_uuid}")
            return jsonify({'status': 'session_already_committed'})

        # Record the confirmation
        if party_name not in pending_session['confirmed']:
            pending_session['confirmed'].append(party_name)
            logging.info(f"Storage confirmation received from '{party_name}' for key UUID: {key_uuid}")

        # Check if all participants have confirmed
        #if sorted(pending_session['confirmed']) == sorted(pending_session['participants']):
        # Check if all original participants are present in the confirmed list
        if set(pending_session['participants']).issubset(set(pending_session['confirmed'])):
            logging.info(f"All parties confirmed for UUID {key_uuid}. Committing key to database.")
            
            # --- FINAL DATABASE WRITE ---
            key = pending_session['key_data']
            try:
                conference_cursor.execute(
                    'INSERT INTO conference_keys (uuid, conference_key, indices, key_length, key_generated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
                    (key['uuid'], key['conference_key'], key['indices'], key['key_length'], key['key_generated_at'], key['expires_at'])
                )
                conference_db_conn.commit()
                logging.info(f"Successfully committed key {key_uuid} to the database.")
            except Exception as e:
                logging.error(f"DATABASE ERROR while committing key {key_uuid}: {e}")
                # If DB write fails, don't log success or clean up, just return an error
                return jsonify({'status': 'error', 'message': 'Failed to commit key to database'}), 500
            start_time = pending_session.get('confirmation_start_time')
            if start_time:
                confirmation_duration = time.time() - start_time   # CONFIRMATION TIME END HERE
                metrics = pending_session['metrics']
                timestamp1 = datetime.datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")
                log_performance(
                    "key_gen_times_parallel_with_polls.csv",
                    "uuid,timestamp,num_clients,key_generation_time_seconds,total_polls,confirmation_duration_seconds",
                    f"{key_uuid},{timestamp1},{metrics['num_clients']},{metrics['key_generation_duration']},{metrics['total_polls']},{confirmation_duration}"
                )
            #  Clean up session and global state
            del pending_sessions[key_uuid]
            parties.clear()  # reset party registry
            session_result = None
            nonce = None
            start_time = None  # reset global timer for next run

        return jsonify({'status': 'confirmation_received'})
# --- Main Execution Block for Setup (Unchanged) ---
if __name__ == '__main__':
    if not (os.path.exists(PUB_KEY_FILE) and os.path.exists(PRIV_KEY_FILE)):
        print(f"Generating PQC keys for '{SERVER_NAME}'...")
        keygen.generate_keys_for(SERVER_NAME)
    
    if not os.path.exists(SECURITY_DB_FILE):
        print(f"Initializing security database '{SECURITY_DB_FILE}'...")
        import manage_allowlist
        manage_allowlist.db_init()

    print("\nServer setup tasks complete.")

    print("To run the truly parallel server, use your runner script (e.g., 'python run_waitress.py').")
