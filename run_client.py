import subprocess
import sys
import time
import os

def run_command(command):
    """
    A helper function to run a command and handle its output.
    Exits the script if a setup command fails.
    """
    try:
        # Run the command, wait for it to complete, and check for errors.
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            check=True,
            encoding='utf-8' # Explicitly set encoding for Windows
        )
        if result.stdout:
            print(result.stdout.strip())
    except subprocess.CalledProcessError as e:
        # If a command fails, print the error and stop the test.
        print(f"--- ERROR running command: {' '.join(command)} ---")
        print(f"Stderr: {e.stderr.strip()}")
        sys.exit(1)

def run_performance_test(num_clients):
    """
    Automates the process of setting up and running a performance test
    with a specified number of clients.
    """
    print(f"--- Starting Performance Test for {num_clients} Clients ---")

    # --- 1. Setup Phase: Generate keys and add clients to allowlist ---
    print("\n[Step 1] Setting up clients...")
    client_names = [f"client{i}" for i in range(num_clients)]
    
    for name in client_names:
        print(f"\nSetting up '{name}'...")
        # Generate keys for the client if they don't exist
        run_command([sys.executable, "keygen.py", name])
        # Add the client to the server's allowlist
        run_command([sys.executable, "manage_allowlist.py", "add", name])

    # --- 2. Launch Phase: Start all client processes in parallel ---
    print("\n[Step 2] Launching all client processes...")
    processes = []
    start_time = time.time()

    for name in client_names:
        # This command is what you would type in each terminal
        command = [sys.executable, "client.py", name]
        
        # Use Popen to launch each client in a new, non-blocking process.
        # This simulates opening multiple terminals.
        proc = subprocess.Popen(command)
        processes.append(proc)
        print(f"  > Launched {name} (Process ID: {proc.pid})")

    # --- 3. Wait Phase: Wait for all clients to finish ---
    print("\n[Step 3] Waiting for all clients to complete...")
    for proc in processes:
        proc.wait() # This will block until the specific client process has finished

    end_time = time.time()
    duration = end_time - start_time
    print("\n--- All client processes have finished. ---")
    print(f"Total test automation script duration: {duration:.2f} seconds")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_test.py <number_of_clients>")
        print("Example: python run_test.py 10")
        sys.exit(1)
    
    try:
        client_count = int(sys.argv[1])
        # MODIFIED: The protocol requires at least 2 clients to reach consensus.
        if client_count <= 1:
            raise ValueError("Number of clients must be greater than 1.")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
        
    run_performance_test(client_count)
