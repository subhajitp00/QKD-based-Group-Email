import sys
from waitress import serve
from pyngrok import ngrok
import atexit

# --- Hardcoded ngrok token ---
NGROK_TOKEN = "replace with your token"  


def start_ngrok(port=5000):
    """Start ngrok tunnel using the hardcoded token."""
    ngrok.set_auth_token(NGROK_TOKEN)
    tunnel = ngrok.connect(port, "http")
    print(f"\n ngrok tunnel active: {tunnel.public_url} → http://127.0.0.1:{port}\n")

    # Clean up on exit
    def cleanup():
        try:
            ngrok.disconnect(tunnel.public_url)
        finally:
            ngrok.kill()
    atexit.register(cleanup)
    return tunnel.public_url


if __name__ == '__main__':
    # --- Default settings ---
    host_mode = "local"  # Default host is localhost

    # --- Parse command-line arguments ---
    if len(sys.argv) > 1:
        host_mode = sys.argv[1].lower()

    # --- Determine host address ---
    if host_mode == "ngrok":
        host_address = '0.0.0.0'
        start_ngrok(5000)
    else:
        host_address = '127.0.0.1'

    # --- Run parallel server ---
    from alice_server_parallel import app
    threads = 10
    print(f'Starting Flask app (Parallel mode, {threads} threads) on http://{host_address}:5000...')
    serve(app, host=host_address, port=5000, threads=threads)

