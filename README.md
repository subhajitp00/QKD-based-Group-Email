# QKD-Based Secure Email System with Conference Key Generation

This project combines **Quantum Key Distribution (QKD)** using the **BB84 protocol** with a **Secure Email Client** to enable **multi-party encrypted communication**. It also includes **performance evaluation scripts** for comparing **QKD-based email (Q-Email)** with **OpenPGP**.

> This framework demonstrates how **quantum-generated conference keys** can be integrated with a real-world email system for secure communication between multiple remote parties.

---

## Quick Start 
1.**First, install all the dependencies mentioned in requirements.txt**
2. **generate public-private key pair for server**
       ```bash
       python keygen.py alice_server   

3. **Start Server**  
      ```bash
        python run_with_waitress.py ngrok // ngrok server
        python run_with_waitress.py    // for local server
4.**Run clients to join the session**
    ```bash
    python run_client.py 2    // for 2 client .
**After completing four steps, the conference key is stored in the local DB.***
5.**Emailing by utilizing conference key**
    ```bash
     python gui.py  // this starts the email client in pop-up windows
6.**Login with your Gmail or Zoho credentials (email ID + App Password)**  
   - For Gmail: create an [App Password](https://support.google.com/accounts/answer/185833) under Google Account → Security → App Passwords.  
   - For Zoho Mail: generate an [App Password here](https://accounts.zoho.com/apppasswords).
**Enjoy QKD safe group emailing**

 

    

