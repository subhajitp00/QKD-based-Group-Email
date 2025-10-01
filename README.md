#Q-email: Multi-party QKD-Based Secure Group Email System  

> Multi-party **BB84** is used to exchange quantum secured conference keys in client-server architecture with mutual authentication by **PQC*"based digital signature **(ML-DSA)**

> This framework demonstrates how **quantum-generated conference keys** can be integrated with a real-world email system for end-to-end secured communication between multiple remote parties.

---

## 🚀 Quick Start

1.  **Install Dependencies**
    First, install all the dependencies mentioned in the `requirements.txt` file.

2.  **Generate Server Keys**
    Create a public-private key pair for the server.
    ```bash
    python keygen.py alice_server
    ```

3.  **Start the Server**
    You can run the server locally or expose it using ngrok.
    ```bash
    # For a local server
    python run_with_waitress.py

    # For an ngrok server
    python run_with_waitress.py ngrok
    ```

4.  **Run Clients**
    Run the client script to join the session. The argument specifies the number of clients.
    ```bash
    # Example for 2 clients
    python run_client.py 2
    ```
    *After these steps are complete, the shared conference key is securely generated and stored in the local database.*

5.  **Launch the Email Client**
    Start the graphical user interface for the secure email client.
    ```bash
    python gui.py
    ```

6.  **Log In to Your Email Account**
    Log in using your email address and an **App Password**.
    -   **Gmail**: Create an [App Password](https://support.google.com/accounts/answer/185833) by navigating to Google Account → Security → App Passwords.
    -   **Zoho Mail**: Generate an [App Password](https://accounts.zoho.com/apppasswords) from your account settings.

**Enjoy QKD-safe group emailing!** 📧✨
