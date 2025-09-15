# QKD-Based Secure Email System with Conference Key Generation

This project combines **Quantum Key Distribution (QKD)** using the **BB84 protocol** with a **Secure Email Client** to enable **multi-party encrypted communication**. It also includes **performance evaluation scripts** for comparing **QKD-based email (Q-Email)** with **OpenPGP**.

> This framework demonstrates how **quantum-generated conference keys** can be integrated with a real-world email system for secure communication between multiple remote parties.

---

## Quick Start (3 Steps)

1. **Start the Conference Key Generation Server**  
   ```bash
   python conference_keygen/run_with_waitress.py ngrok
   python conference_keygen/run_with_waitress.py 
2.**Run clients to join the session**
