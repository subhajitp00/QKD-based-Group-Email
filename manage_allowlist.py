# manage_allowlist.py
import sqlite3
import datetime
import os
import argparse

DB_FILE = "security.db"
KEY_SUFFIX = "_dilithium.pub"

def db_init():
    """Initializes the database and allowlist table."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS allowlist (
                party_name TEXT PRIMARY KEY,
                public_key_hex TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('active', 'expired', 'revoked'))
            )
        ''')
        conn.commit()

def add_client(party_name, days_valid):
    """Adds a new client to the allowlist from their public key file."""
    pub_key_file = f"{party_name}{KEY_SUFFIX}"
    if not os.path.exists(pub_key_file):
        print(f" ERROR: Public key file '{pub_key_file}' not found. Please run keygen.py for '{party_name}' first.")
        return

    with open(pub_key_file, "rb") as f:
        public_key_hex = f.read().hex()

    created_at = datetime.datetime.now(datetime.timezone.utc)
    expires_at = created_at + datetime.timedelta(days=days_valid)
    
    created_at_iso = created_at.strftime('%Y-%m-%d %H:%M:%S')
    expires_at_iso = expires_at.strftime('%Y-%m-%d %H:%M:%S')

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT OR REPLACE INTO allowlist (party_name, public_key_hex, created_at, expires_at, status) VALUES (?, ?, ?, ?, ?)",
                (party_name, public_key_hex, created_at_iso, expires_at_iso, 'active')
            )
            conn.commit()
            print(f"Client '{party_name}' added to the allowlist. Access expires on {expires_at_iso} UTC.")
        except sqlite3.IntegrityError:
            print(f"lient '{party_name}' already exists in the allowlist. Use 'update' command if needed.")

def view_allowlist():
    """Prints the contents of the allowlist table."""
    print("\n--- Client Allowlist (security.db) ---")
    if not os.path.exists(DB_FILE):
        print("Database does not exist. Add a client to create it.")
        return
        
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT party_name, status, created_at, expires_at FROM allowlist")
        rows = cursor.fetchall()
        
        if not rows:
            print("Allowlist is empty.")
            return

        print(f"{'Party Name':<15} {'Status':<10} {'Created At (UTC)':<22} {'Expires At (UTC)':<22}")
        print("-" * 72)
        for row in rows:
            print(f"{row['party_name']:<15} {row['status']:<10} {row['created_at']:<22} {row['expires_at']:<22}")

if __name__ == "__main__":
    db_init()
    parser = argparse.ArgumentParser(description="Manage the client allowlist.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    parser_add = subparsers.add_parser("add", help="Add a new client to the allowlist.")
    parser_add.add_argument("name", help="The name of the party to add (e.g., bob).")
    parser_add.add_argument("--days", type=int, default=30, help="Number of days the key is valid for (default: 30).")
    parser_view = subparsers.add_parser("view", help="View all clients on the allowlist.")
    args = parser.parse_args()

    if args.command == "add":
        add_client(args.name.lower(), args.days)
    elif args.command == "view":
        view_allowlist()