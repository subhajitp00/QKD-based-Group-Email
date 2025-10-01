# client.py
import sys
import os
import random
import time
import requests
import sqlite3
import numpy as np
import math
import hashlib
import datetime
from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer
from dilithium_py.dilithium import Dilithium2
import keygen  # Assuming keygen.py is in the same directory
# --- Configuration and Setup ---
# The server URL is now hardcoded again for simplicity.
# For remote connections, you would change this line to the ngrok URL provided by the server.
#ALICE_URL = "https://c7377d5585bc.ngrok-free.app"
ALICE_URL = "http://127.0.0.1:5000"  # Local server URL
SERVER_PUB_KEY_FILE = "alice_server_dilithium.pub"
BACKEND = Aer.get_backend("qasm_simulator")

# --- Helper Functions (Unchanged) ---
def measure_circuits(circuits, bases):
    """Measures a list of quantum circuits with specified bases."""
    results = []
    for ops, basis in zip(circuits, bases):
        qc = QuantumCircuit(1, 1)
        for op in ops:
            if op == "x": qc.x(0)
            elif op == "h": qc.h(0)
        if basis: qc.h(0)
        qc.measure(0, 0)
        qc=transpile(qc, backend=BACKEND)
        counts = BACKEND.run(qc, shots=1).result().get_counts()
        results.append(int(list(counts.keys())[0]))
    return results

def KDF(input_string, length=32):
    """A simple Key Derivation Function using SHA-256."""
    return bin(int(hashlib.sha256(input_string.encode()).hexdigest(), 16))[2:].zfill(256)[:length]

def wait_for_consensus(party_name, bases, results, max_attempts=20, poll_interval=3):
    """Polls the server until all parties have submitted keys and consensus is reached."""
    print(f"\n[{party_name.upper()}] Waiting for other parties to complete key exchange...")
    for attempt in range(max_attempts):
        time.sleep(poll_interval)
        print(f"  > Polling server for consensus (attempt {attempt+1}/{max_attempts})...")
        try:
            # This payload now matches what the server expects
            payload = {"bases": bases.tolist(), "results": results}
            resp = requests.post(f"{ALICE_URL}/sift/{party_name}", json=payload)
            
            resp.raise_for_status()
            data = resp.json()
            if data.get('status') == 'consensus_reached':
                print(f"  >  Consensus reached for {party_name}!")
                return data
        except requests.exceptions.RequestException as e:
            print(f"  >  Could not poll server: {e}")

    raise RuntimeError(f"Failed to reach consensus for {party_name}.")

# --- Main Client Logic ---
def run_client(party_name):
    """
    Executes the full client-side protocol for a given party name.
    """
    # --- Setup client-specific files ---
    priv_key_file = f"{party_name}_dilithium.key"
    db_file = f"{party_name}_conference_keys.db"

    print(f"\n--- Starting Client: {party_name.upper()} ---")
    print(f"  > Connecting to Server: {ALICE_URL}")

    keygen.generate_keys_for(party_name)
    
    # --- STEP 1: MUTUAL AUTHENTICATION ---
    print("\n[Step 1] Initiating Mutual Authentication...")
    
    # Part A: Client Verifies Server's Identity
    print("  > Challenging server to prove its identity...")
    try:
        with open(SERVER_PUB_KEY_FILE, 'rb') as f:
            server_public_key = f.read()
    except FileNotFoundError:
        print(f" ERROR: Server public key file '{SERVER_PUB_KEY_FILE}' not found.")
        print("  > Please copy it from the server machine to this directory.")
        return

    client_challenge = ''.join(random.choice('0123456789abcdef') for _ in range(32))
    try:
        response = requests.post(f"{ALICE_URL}/prove_identity", json={'challenge': client_challenge}, timeout=10)
        response.raise_for_status()
        server_signature = bytes.fromhex(response.json().get('signature'))
    except requests.exceptions.RequestException as e:
        print(f" ERROR: Could not connect to the server at {ALICE_URL}. Is it running? Details: {e}")
        return
    
    if Dilithium2.verify(server_public_key, client_challenge.encode(), server_signature):
        print("  > SUCCESS: Server identity verified.")
    else:
        print("  > DANGER: Server signature is NOT valid. Aborting.")
        return

    # Part B: Client Proves Its Identity to Server
    print("\n  > Now, proving our identity to the server...")
    try:
        start_resp = requests.post(f"{ALICE_URL}/start/{party_name}").json()
        pqc_challenge = start_resp.get('pqc_challenge')
        nonce, n_bits = start_resp['nonce'], start_resp['n_bits']
        kdf_key_length = start_resp['desired_key_length']
        kdf_size = start_resp['kdf_size']
        print(f"  > Received challenge from server: {pqc_challenge}")
    except requests.exceptions.RequestException as e:
        print(f" ERROR: Could not start session with server. Details: {e}"); return

    with open(priv_key_file, "rb") as f:
        private_key = f.read()
    signature = Dilithium2.sign(private_key, pqc_challenge.encode())
    print("  > Challenge signed with our private key.")

    auth_payload = {'party_name': party_name, 'signature': signature.hex()}
    try:
        auth_resp = requests.post(f"{ALICE_URL}/authenticate", json=auth_payload)
        auth_resp.raise_for_status()
        status = auth_resp.json().get('status')
    except requests.exceptions.RequestException as e:
        print(f" ERROR: Authentication request failed. Server responded with: {e.response.text if e.response else 'No Response'}")
        return
    
    if status != 'authenticated':
        print(f"  >  FAILED! Server rejected our authentication. Reason: {status}")
        return
    
    print(f"  >  SUCCESS! Server has authenticated us.")
    print("\nMutual authentication complete. Proceeding to BB84 Key Exchange.")

    # --- STEP 2: BB84 KEY EXCHANGE ---
    print("\n[Step 2] Performing BB84 Protocol...")
    qubits_data = requests.get(f"{ALICE_URL}/qubits/{party_name}").json()
    client_bases = np.random.randint(2, size=n_bits)
    client_results = measure_circuits(qubits_data['circuits'], client_bases)
    print("  > Measured incoming qubits from server.")
    
    bases_data = requests.get(f"{ALICE_URL}/bases/{party_name}").json()
    alice_bases = bases_data.get('bases', [])
    print("  > Received Alice's (server's) bases for sifting.")
    
    initial_payload = {"bases": client_bases.tolist(), "results": client_results}
    response = requests.post(
        f"{ALICE_URL}/sift/{party_name}", 
        json=initial_payload
    )

    # Check for HTTP errors (like 500 Internal Server Error)
    if response.status_code != 200:
        print(f" ERROR: Server returned an error (HTTP {response.status_code}).")
        try:
            # Try to print the JSON error message from the server
            error_data = response.json()
            print(f"  > Server Details: {error_data.get('error')} - {error_data.get('details')}")
        except requests.exceptions.JSONDecodeError:
            # If the response wasn't JSON, print the raw text
            print(f"  > Server response was not valid JSON:\n{response.text}")
        return # Stop the client
    sift_data = response.json()

    if sift_data.get('status') != 'consensus_reached':
        sift_data = wait_for_consensus(party_name, client_bases, client_results)

    # --- STEP 3: CONFERENCE KEY DERIVATION ---
    print("\n[Step 3] Deriving final conference key...")
    mask = (np.array(client_bases) == np.array(alice_bases))
    client_sifted = np.array(client_results)[mask]
    sifted_key_str = ''.join(map(str, client_sifted))
    
    num_blocks = math.ceil(kdf_key_length / kdf_size)
    public_info = [f"p{i+1}" for i in range(num_blocks)]
    extended_key = "".join([KDF(sifted_key_str + nonce + p, kdf_size) for p in public_info])[:kdf_key_length]

    indices = sift_data.get('conference_key_indices', [])
    local_conf_key = ''.join(extended_key[i] for i in indices)
    conf_key_uuid = sift_data.get('conference_key_uuid')
    expires_at = sift_data.get('expires_at')
    key_generated_at = sift_data.get('key_generated_at')

    print(f"  > Locally derived conference key of length {len(local_conf_key)} bits.")
    # --- NEW CONFIRMATION STEP ---
    try:
        print(f"  > Sending storage confirmation to server for {conf_key_uuid}...")
        confirm_payload = {'uuid': conf_key_uuid, 'party_name': party_name}
        
        # Send the confirmation and check for a successful response
        response = requests.post(f"{ALICE_URL}/confirm_storage", json=confirm_payload, timeout=15)
        response.raise_for_status() # This will raise an error for 4xx or 5xx status codes
        
        print("  >  Confirmation successfully sent and acknowledged by server.")
    except requests.exceptions.RequestException as e:
        print(f"  >  WARNING: Could not send storage confirmation to server. The key is saved locally, but the server may not know. Details: {e}")
        return
    # --- SAVE FINAL KEY ---
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS conference_keys (
        uuid TEXT PRIMARY KEY, 
        conference_key TEXT NOT NULL, 
        indices TEXT NOT NULL,
        key_length TEXT NOT NULL, 
        key_generated_at TEXT NOT NULL, 
        expires_at TEXT NOT NULL
    )''')
    # CORRECTED the column names 'key_length' and 'expires_at'
    cursor.execute("INSERT OR REPLACE INTO conference_keys (uuid, conference_key, indices, key_length, key_generated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                   (conf_key_uuid, local_conf_key, ','.join(map(str, indices)), len(local_conf_key), key_generated_at, expires_at))
    conn.commit()
    print(f"\n Conference key saved to '{db_file}' with UUID: {conf_key_uuid}")
     

# --- MODIFIED: Main execution block uses simple sys.argv parsing ---
if __name__ == "__main__":
    # Check if a party name was provided on the command line
    if len(sys.argv) < 2:
        print("Usage: python client.py <party_name>")
        print("Example: python client.py bob")
        sys.exit(1)
    
    # The first argument after the script name is the party's name
    party_name = sys.argv[1].lower()
    
    # Run the client with the provided name

    run_client(party_name)
