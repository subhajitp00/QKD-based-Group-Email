#!/usr/bin/env python3
"""
Working Encryption Utilities for QKD Email Client
Provides AES-192 CBC encryption for messages and file attachments
"""

import base64
import os
import sqlite3
import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

DB_FILE = "conference_keys.db"

def is_key_expired(expires_at_string: str) -> bool:
    """
    Checks if a key has expired by comparing its UTC expiry time
    to the current UTC time.

    Args:
        expires_at_string: The ISO 8601 timestamp string from the server.

    Returns:
        True if the key is expired, False otherwise.
    """
    try:
        expiry_time_utc = datetime.datetime.fromisoformat(expires_at_string)
        current_time_utc = datetime.datetime.now(datetime.timezone.utc)
        is_expired = current_time_utc >= expiry_time_utc

        print(f"      - Current UTC Time: {current_time_utc.isoformat()}")
        print(f"      - Key Expires (UTC):  {expiry_time_utc.isoformat()}")
        print(f"      - Is Expired?:      {is_expired}")

        return is_expired

    except (ValueError, TypeError) as e:
        print(f"Error: Could not parse timestamp '{expires_at_string}'. Error: {e}")
        return True

def get_key_by_uuid(uuid, db_file=DB_FILE):
    """
    Retrieves a non-expired encryption key by its UUID from the database.
    The key is validated and padded/truncated to 24 bytes for AES-192.
    """
    print(f"[CRYPTO] Attempting to get key for UUID: {uuid}")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT conference_key, expires_at FROM conference_keys WHERE uuid=?", (uuid,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        print(f"[CRYPTO] FAILURE: No key found for UUID: {uuid}")
        raise Exception("No key found for the given UUID.")
    
    # --- CORRECTED: The variable from the database is 'key', not 'conference_key'. ---
    key, expires_at = row
    if is_key_expired(expires_at):
        print(f"[CRYPTO] FAILURE: Key for UUID {uuid} has expired at {expires_at}.")
        raise Exception("Key is expired or invalid for this UUID.")

    print(f"[CRYPTO] SUCCESS: Retrieved valid key for UUID: {uuid}")
    
    if isinstance(key, str):
        key = key.encode('utf-8')

    # Ensure key is 24 bytes for AES-192
    if len(key) > 24:
        key = key[:24]
    elif len(key) < 24:
        key = key.ljust(24, b'\0')
    return key

def get_latest_valid_uuid(db_file=DB_FILE):
    """Finds the most recent, non-expired conference key UUID."""
    print("[CRYPTO] Searching for the latest valid conference key UUID...")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    # --- CORRECTED: Changed "ORDER BY key" to "ORDER BY key_generated_at" for consistency. ---
    cursor.execute("SELECT uuid, expires_at FROM conference_keys ORDER BY key_generated_at DESC")
    for uuid, expires_at in cursor.fetchall():
        if not is_key_expired(expires_at):
            conn.close()
            print(f"[CRYPTO] Found latest valid UUID: {uuid}")
            return uuid
    conn.close()
    print("[CRYPTO] FAILURE: No valid (non-expired) conference key UUID found.")
    raise Exception("No valid (non-expired) conference key UUID found.")

def list_all_valid_uuids(db_file=DB_FILE):
    """Returns a list of all non-expired key UUIDs for decryption attempts."""
    print("[CRYPTO] Listing all valid UUIDs for decryption trial...")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT uuid, expires_at FROM conference_keys")
    valid_uuids = []
    for uuid, expires_at_str in cursor.fetchall():
        if not is_key_expired(expires_at_str):
            valid_uuids.append(uuid)
    conn.close()
    print(f"[CRYPTO] Found {len(valid_uuids)} valid UUID(s).")
    return valid_uuids

def get_latest_key_expiry(db_file=DB_FILE):
    """
    Finds the UUID and expiration time string of the most recent, non-expired key.
    Returns (uuid, expires_at_str) or (None, None) if no valid key is found.
    """
    print("[CRYPTO] Searching for the latest valid key to get its expiry time...")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT uuid, expires_at FROM conference_keys ORDER BY key_generated_at DESC")
    for uuid, expires_at in cursor.fetchall():
        if not is_key_expired(expires_at):
            conn.close()
            print(f"[CRYPTO] Found latest valid key {uuid} expiring at {expires_at}")
            return uuid, expires_at
    conn.close()
    print("[CRYPTO] No valid (non-expired) key found.")
    return None, None

def encrypt_message(message: str, key: bytes) -> str:
    """Encrypts a string using AES-192 CBC and returns a base64 encoded string."""
    print(f"[CRYPTO] Encrypting message (length: {len(message)} chars)...")
    if not isinstance(message, str):
        message = str(message)
    cipher = AES.new(key, AES.MODE_CBC)
    padded_data = pad(message.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    combined = cipher.iv + ciphertext
    b64_result = base64.b64encode(combined).decode('utf-8')
    print("[CRYPTO] Message encryption complete.")
    return b64_result

def decrypt_message(ciphertext: str, key: bytes) -> str:
    """Decrypts a base64 encoded string using AES-192 CBC."""
    print(f"[CRYPTO] Decrypting message (length: {len(ciphertext)} chars)...")
    raw_data = base64.b64decode(ciphertext)
    iv = raw_data[:16]
    encrypted_data = raw_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(encrypted_data)
    plaintext = unpad(padded_plaintext, AES.block_size)
    print("[CRYPTO] Message decryption complete.")
    return plaintext.decode('utf-8', errors='ignore')

def encrypt_file_to_base64(file_path: str, key: bytes) -> tuple:
    """Encrypts a file, returns its base64 content and new filename."""
    print(f"[CRYPTO] Encrypting file: {file_path}")
    with open(file_path, 'rb') as f:
        file_data = f.read()
    print(f"[CRYPTO] Read {len(file_data)} bytes from file.")
    cipher = AES.new(key, AES.MODE_CBC)
    padded_data = pad(file_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    combined = cipher.iv + encrypted_data
    result = base64.b64encode(combined).decode('utf-8')
    enc_filename = os.path.basename(file_path) + ".enc"
    print(f"[CRYPTO] File encryption complete. Output filename: {enc_filename}")
    return result, enc_filename

def decrypt_file_from_base64(base64_data: str, key: bytes, output_path: str) -> None:
    """Decrypts base64 data and saves it to a file."""
    print(f"[CRYPTO] Decrypting file data to be saved at: {output_path}")
    raw_data = base64.b64decode(base64_data)
    iv = raw_data[:16]
    encrypted_data = raw_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(encrypted_data)
    file_data = unpad(padded_plaintext, AES.block_size)
    dir_name = os.path.dirname(output_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(file_data)
    print(f"[CRYPTO] File decryption complete. Saved {len(file_data)} bytes to {output_path}")