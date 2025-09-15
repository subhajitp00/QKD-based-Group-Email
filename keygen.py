# keygen.py
import os
import sys
from dilithium_py.dilithium import Dilithium2

def generate_keys_for(party_name):
    """Generates and saves a Dilithium key pair for a given party."""
    pub_key_file = f"{party_name}_dilithium.pub"
    priv_key_file = f"{party_name}_dilithium.key"

    if os.path.exists(pub_key_file) and os.path.exists(priv_key_file):
        # Keys already exist, no action needed.
        return

    print(f"Generating new Dilithium key pair for '{party_name}'...")
    
    public_key, private_key = Dilithium2.keygen()
    
    with open(pub_key_file, "wb") as f:
        f.write(public_key)
    with open(priv_key_file, "wb") as f:
        f.write(private_key)
            
    print(f" Keys for '{party_name}' saved to '{pub_key_file}' and '{priv_key_file}'.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python keygen.py <party_name_1> [party_name_2] ...")
        print("Example: python keygen.py alice_server bob charlie")
        sys.exit(1)
    
    for party in sys.argv[1:]:
        generate_keys_for(party.lower())