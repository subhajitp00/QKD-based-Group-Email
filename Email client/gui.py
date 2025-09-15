#!/usr/bin/env python3
"""
Complete Working and Corrected GUI for Secure QKD Email Client
Features: Interactive login, email sending, fetching, attachment encryption, and a diagnostics tab.
"""

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import time
import base64
import email.utils
import itertools
import datetime
import psutil

# Import our working modules
from working_mail_utils import EmailClient
from working_encryption_utils import (
    get_key_by_uuid, get_latest_valid_uuid, list_all_valid_uuids,
    encrypt_message, decrypt_message, encrypt_file_to_base64, decrypt_file_from_base64, get_latest_key_expiry
)

class SecureQKDEmailGUI(tk.Tk):
    """Main GUI application for the secure QKD email client"""
    
    def __init__(self):
        super().__init__()
        self.title("Secure QKD Email Client")
        self.geometry("1000x750")
        self.configure(bg='#f0f0f0')
        
        # Styles
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("Success.TLabel", foreground="green", font=("Arial", 10, "bold"))
        self.style.configure("Error.TLabel", foreground="red", font=("Arial", 10, "bold"))
        self.style.configure("Info.TLabel", foreground="blue", font=("Arial", 10))
        self.style.configure("Accent.TButton", foreground="white", background="#27ae60", font=("Arial", 11, "bold"))
        self.style.map("Accent.TButton", background=[('active', '#2ecc71'), ('disabled', '#95a5a6')])

        # State variables
        self.provider = tk.StringVar(value="Zoho India")
        self.email_id = tk.StringVar()
        self.password = tk.StringVar()
        self.attach_plain, self.attach_enc, self.messages = [], [], []
        self.client = None
        self.is_logging_in, self.is_sending, self.is_fetching = False, False, False
        
        self.performance_data = {
            "Last Send Time (s)": "N/A",
            "Last Encryption Time (s)": "N/A",
            "Last Fetch Time (s)": "N/A",
            "Last Decryption Time (s)": "N/A",
            "Message Overhead Ratio": "N/A",
            "Attachment Overhead Ratio": "N/A",
        }
        
        print("[LOG] GUI Initialized. Building UI...")
        self._build_ui()
        self._setup_status_bar()
        print("[LOG] UI build complete.")

    def _build_ui(self):
        """Build the main user interface with tabs."""
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill="both", expand=True)
        
        self.notebook = ttk.Notebook(main_frame)
        self.tab_login = ttk.Frame(self.notebook)
        self.tab_mail = ttk.Frame(self.notebook)
        self.tab_diagnostics = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab_login, text="🔐 Login")
        self.notebook.add(self.tab_mail, text="📧 Email", state="disabled")
        self.notebook.add(self.tab_diagnostics, text="📊 Diagnostics", state="disabled")
        self.notebook.pack(fill="both", expand=True)
        
        self._build_login_tab()
        self._build_mail_tab()
        self._build_diagnostics_tab()

    def _build_login_tab(self):
        """Builds the widgets for the login tab."""
        style = self.style
        style.configure("Blue.TLabelframe", background="#ecf0f1")
        style.configure("Blue.TLabelframe.Label", foreground="#2980b9", font=("Arial", 16, "bold"))
        style.configure("Green.TLabelframe", background="#ecf0f1")
        style.configure("Green.TLabelframe.Label", foreground="#27ae60", font=("Arial", 16, "bold"))

        login_container = ttk.Frame(self.tab_login, padding=20, style="Blue.TLabelframe")
        login_container.pack(expand=True, fill="both")
        center_frame = ttk.Frame(login_container, style="Blue.TLabelframe")
        center_frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(center_frame, text="🔒 Secure QKD Email Client", font=("Arial", 28, "bold"), foreground="#2c3e50", background="#ecf0f1").pack(pady=(0, 32))

        provider_frame = ttk.LabelFrame(center_frame, text="📡 Select Email Provider", padding=15, style="Blue.TLabelframe")
        provider_frame.pack(fill="x", pady=20)
        ttk.Radiobutton(provider_frame, text="🏢 Zoho India", variable=self.provider, value="Zoho India").pack(anchor="w", pady=6)
        ttk.Radiobutton(provider_frame, text="📬 Gmail India", variable=self.provider, value="Gmail India").pack(anchor="w", pady=6)

        creds_frame = ttk.LabelFrame(center_frame, text="🔑 Enter Credentials", padding=15, style="Green.TLabelframe")
        creds_frame.pack(fill="x", pady=30)
        ttk.Label(creds_frame, text="Email Address:", font=("Arial", 12, "bold"), foreground="#34495e", background="#ecf0f1").grid(row=0, column=0, sticky="e", padx=8, pady=8)
        email_entry = ttk.Entry(creds_frame, textvariable=self.email_id, font=("Arial", 12), width=36)
        email_entry.grid(row=0, column=1, sticky="ew", pady=8)
        ttk.Label(creds_frame, text="Password / App Password:", font=("Arial", 12, "bold"), foreground="#34495e", background="#ecf0f1").grid(row=1, column=0, sticky="e", padx=8, pady=8)
        password_entry = ttk.Entry(creds_frame, textvariable=self.password, font=("Arial", 12), show="*", width=36)
        password_entry.grid(row=1, column=1, sticky="ew", pady=8)
        password_entry.bind("<Return>", lambda event: self._initiate_login())
        creds_frame.columnconfigure(1, weight=1)

        self.login_btn = ttk.Button(center_frame, text="🚀 Connect", command=self._initiate_login, style="Accent.TButton")
        self.login_btn.pack(pady=12)

        self.login_status_frame = ttk.Frame(center_frame, style="Blue.TLabelframe")
        self.login_status_frame.pack(fill="x")
        self.login_spinner = ttk.Label(self.login_status_frame, font=("Arial", 12))
        self.login_status_label = ttk.Label(self.login_status_frame, font=("Arial", 12, "italic"), foreground="#d35400", background="#ecf0f1")
        self.login_status_label.pack(side="left", padx=10)

    def _build_mail_tab(self):
        """Builds the widgets for the main email functionality tab."""
        style = self.style
        style.configure('green.Horizontal.TProgressbar', background='#27ae60')
        paned_window = ttk.PanedWindow(self.tab_mail, orient="vertical")
        paned_window.pack(fill="both", expand=True, padx=14, pady=14)

        # Compose Section
        compose_frame = ttk.LabelFrame(paned_window, text="✍️ Compose Encrypted Email", padding=12, style="Blue.TLabelframe")
        paned_window.add(compose_frame, weight=1)
        fields_frame = ttk.Frame(compose_frame, style="Blue.TLabelframe")
        fields_frame.pack(fill="x", pady=(0, 14))
        ttk.Label(fields_frame, text="To:", font=("Arial", 12, "bold")).grid(row=0, column=0, sticky="e", padx=7)
        self.to_entry = ttk.Entry(fields_frame, width=48)
        self.to_entry.grid(row=0, column=1, sticky="ew", pady=2)
        ttk.Label(fields_frame, text="Subject:", font=("Arial", 12, "bold")).grid(row=1, column=0, sticky="e", padx=7)
        self.subject_entry = ttk.Entry(fields_frame, width=48)
        self.subject_entry.grid(row=1, column=1, sticky="ew", pady=2)
        fields_frame.columnconfigure(1, weight=1)
        body_frame = ttk.Frame(compose_frame, style="Blue.TLabelframe")
        body_frame.pack(fill="both", expand=True, pady=10)
        ttk.Label(body_frame, text="Message:", font=("Arial", 11, "bold")).pack(anchor="w")
        self.message_text = tk.Text(body_frame, height=6, wrap="word", font=("Arial", 11))
        self.message_text.pack(side="left", fill="both", expand=True)
        attach_frame = ttk.Frame(compose_frame, style="Blue.TLabelframe")
        attach_frame.pack(fill="x", pady=10)
        #ttk.Button(attach_frame, text="📎 Attach File", command=self._add_attachment, style="Accent.TButton").pack(side="left", padx=6)
        ttk.Button(attach_frame, text="🔒 Attachment", command=self._add_encrypted_attachment, style="Accent.TButton").pack(side="left", padx=6)
        self.attachment_label = ttk.Label(attach_frame, text="No attachments", font=("Arial", 10, "italic"))
        self.attachment_label.pack(side="left", padx=22)
        self.send_btn = ttk.Button(attach_frame, text="📤 Send Encrypted Email", command=self._initiate_send, style="Accent.TButton")
        self.send_btn.pack(side="right", padx=6)
        send_status_container = ttk.Frame(compose_frame)
        send_status_container.pack(fill="x", pady=5)
        self.send_spinner = ttk.Label(send_status_container, font=("Arial", 12))
        self.send_progress = ttk.Progressbar(send_status_container, mode="determinate", length=200, style='green.Horizontal.TProgressbar')
        self.send_status_label = ttk.Label(send_status_container, font=("Arial", 11), foreground="#27ae60")

        # Inbox Section
        inbox_frame = ttk.LabelFrame(paned_window, text="📬 Inbox", padding=12, style="Blue.TLabelframe")
        paned_window.add(inbox_frame, weight=2)
        inbox_controls = ttk.Frame(inbox_frame)
        inbox_controls.pack(fill="x", pady=(0, 10))
        self.fetch_btn = ttk.Button(inbox_controls, text="📥 Fetch Emails", command=self._initiate_fetch, style="Accent.TButton")
        self.fetch_btn.pack(side="left", padx=4)
        ttk.Button(inbox_controls, text="💾 Save Attachments", command=self._save_attachments, style="Accent.TButton").pack(side="left", padx=12)
        fetch_status_container = ttk.Frame(inbox_controls)
        fetch_status_container.pack(side="right", fill="x")
        self.fetch_spinner = ttk.Label(fetch_status_container, font=("Arial", 12))
        self.fetch_status_label = ttk.Label(fetch_status_container, text="", font=("Arial", 11), foreground="#2e86c1")
        list_frame = ttk.Frame(inbox_frame)
        list_frame.pack(fill="both", expand=True)
        self.email_listbox = tk.Listbox(list_frame, font=("Arial", 10), bg="#f7f9f9")
        self.email_listbox.bind("<<ListboxSelect>>", self._show_email)
        self.email_listbox.pack(side="left", fill="both", expand=True)
        display_frame = ttk.Frame(inbox_frame)
        display_frame.pack(fill="both", expand=True, pady=(10, 0))
        self.email_display = tk.Text(display_frame, height=10, wrap="word", state="disabled", font=("Arial", 10), background="#ecf0f1")
        self.email_display.pack(side="left", fill="both", expand=True)

    def _build_diagnostics_tab(self):
        """Builds the widgets for the performance diagnostics tab."""
        diag_frame = ttk.Frame(self.tab_diagnostics, padding="10")
        diag_frame.pack(fill="both", expand=True)

        self.diag_tree = ttk.Treeview(diag_frame, columns=('Metric', 'Value'), show='headings')
        self.diag_tree.heading('Metric', text='Performance Metric')
        self.diag_tree.heading('Value', text='Value')
        self.diag_tree.column('Metric', width=250)
        self.diag_tree.pack(fill="both", expand=True, pady=5)

        refresh_button = ttk.Button(diag_frame, text="🔄 Refresh Live Stats",
                                    command=self._update_diagnostics_display, style="Accent.TButton")
        refresh_button.pack(pady=10)

    def _update_diagnostics_display(self):
        """Clears and repopulates the diagnostics tree with the latest data."""
        for item in self.diag_tree.get_children():
            self.diag_tree.delete(item)

        for key, value in self.performance_data.items():
            self.diag_tree.insert("", "end", values=(key, value))

        try:
            process = psutil.Process(os.getpid())
            cpu_percent = process.cpu_percent(interval=0.1)
            memory_mb = process.memory_info().rss / (1024 * 1024)
            
            self.diag_tree.insert("", "end", values=("CPU Usage (%)", f"{cpu_percent:.2f}"))
            self.diag_tree.insert("", "end", values=("Memory Usage (MB)", f"{memory_mb:.2f}"))
        except Exception as e:
            print(f"[ERROR] Could not get resource stats: {e}")
            self.diag_tree.insert("", "end", values=("CPU Usage (%)", "Error"))
            self.diag_tree.insert("", "end", values=("Memory Usage (MB)", "Error"))

    def _animate_spinner(self, label, spinner_chars):
        if label.winfo_exists() and getattr(label, 'spinning', False):
            label.config(text=next(spinner_chars))
            self.after(150, lambda: self._animate_spinner(label, spinner_chars))

    def _toggle_spinner(self, label, start):
        if start:
            label.spinning = True
            chars = itertools.cycle("⭮⭯⭰⭱")
            self._animate_spinner(label, chars)
            label.pack(side="left", padx=5)
        else:
            label.spinning = False
            label.pack_forget()

    def _setup_status_bar(self):
        """Sets up the bottom status bar using the .grid() manager for stability."""
        self.status_frame = ttk.Frame(self, relief="sunken", padding="5")
        self.status_frame.pack(fill="x", side="bottom")

        self.status_frame.columnconfigure(1, weight=1)

        self.status_label = ttk.Label(self.status_frame, text="Ready - Please login", font=("Arial", 9))
        self.status_label.grid(row=0, column=0, sticky="w")
        
        self.key_expiry_label = ttk.Label(self.status_frame, text="", font=("Arial", 9, "bold"))
        self.key_expiry_label.grid(row=0, column=1, sticky="w", padx=20)

        self.connection_indicator = ttk.Label(self.status_frame, text="⚫ Disconnected",
                                            foreground="red", font=("Arial", 9))
        self.connection_indicator.grid(row=0, column=2, sticky="e")

    def _update_countdown_timer(self, uuid, expiry_datetime):
        """Updates the key expiry countdown label every second, including the UUID."""
        now = datetime.datetime.now(datetime.timezone.utc)
        remaining = expiry_datetime - now

        if remaining.total_seconds() <= 0:
            self.key_expiry_label.config(text=f"⚠️ Key {uuid[:8]}... Expired!", foreground="red")
            return

        hours, remainder = divmod(int(remaining.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        countdown_str = f"{hours:02}:{minutes:02}:{seconds:02}"

        if remaining.total_seconds() < 300:
            self.key_expiry_label.config(foreground="orange")
        else:
            self.key_expiry_label.config(foreground="green")

        self.key_expiry_label.config(text=f"🔑 Key {uuid[:8]}... expires in: {countdown_str}")

        self.after(1000, self._update_countdown_timer, uuid, expiry_datetime)

    def _initiate_login(self):
        print("[LOG] Login process initiated by user.")
        if self.is_logging_in: return
        email, password = self.email_id.get().strip(), self.password.get().strip()
        if not email or not password:
            messagebox.showwarning("Input Required", "Please enter both email and password.")
            return
        self.is_logging_in = True
        self._set_login_state(True)
        print("[LOG] Starting login background thread...")
        threading.Thread(target=self._perform_login, args=(email, password), daemon=True).start()

    def _perform_login(self, email, password):
        print("[LOG] Login thread started.")
        try:
            self.after(0, lambda: self._show_login_status("🔍 Verifying...", "info"))
            self.client = EmailClient(self.provider.get())
            print("[LOG] Testing connection by fetching 1 email...")
            self.client.fetch_emails(email, password, count=1)
            self.after(0, self._login_success)
        except Exception as e:
            print(f"[ERROR] Exception in login thread: {e}")
            self.after(0, lambda msg=str(e): self._login_failed(msg))

    def _login_success(self):
        """Handle successful login and start the key expiry countdown."""
        print("[LOG] Login successful. Updating GUI.")
        self.is_logging_in = False
        self._set_login_state(False)
        self.notebook.tab(self.tab_mail, state="normal")
        self.notebook.tab(self.tab_diagnostics, state="normal")
        self.notebook.select(self.tab_mail)
        
        self._show_status(f"✅ Logged in as {self.email_id.get()}", "success")
        self.connection_indicator.config(text="🟢 Connected", foreground="green")
        self.login_status_label.config(text="")
        
        self._update_diagnostics_display()

        print("[LOG] Starting key expiry countdown timer...")
        try:
            uuid, expiry_str = get_latest_key_expiry()
            if expiry_str:
                # --- CORRECTED: Use fromisoformat to handle the UTC timestamp from the DB ---
                expiry_dt = datetime.datetime.fromisoformat(expiry_str)
                self._update_countdown_timer(uuid, expiry_dt)
            else:
                self.key_expiry_label.config(text="⚠️ No valid key found!", foreground="red")
        except Exception as e:
            print(f"[ERROR] Could not start key expiry timer: {e}")
            self.key_expiry_label.config(text="⚠️ Key status unknown!", foreground="red")

    def _login_failed(self, error_msg):
        print(f"[LOG] Login failed. Updating GUI with error: {error_msg}")
        self.is_logging_in = False
        self._set_login_state(False)
        self._show_login_status(f"❌ Login failed: {error_msg}", "error")
        self._show_status("❌ Login failed", "error")

    def _set_login_state(self, logging_in):
        self.login_btn.config(state="disabled" if logging_in else "normal")
        self.login_btn.config(text="🔄 Connecting..." if logging_in else "🚀 Connect")
        self._toggle_spinner(self.login_spinner, logging_in)

    def _show_login_status(self, message, status_type):
        styles = {"info": "Info.TLabel", "success": "Success.TLabel", "error": "Error.TLabel"}
        self.login_status_label.config(text=message, style=styles.get(status_type, ""))

    def _initiate_send(self):
        print("[LOG] Send process initiated by user.")
        if self.is_sending: return
        to_addrs, subject, message = self.to_entry.get().strip(), self.subject_entry.get().strip(), self.message_text.get("1.0", "end-1c").strip()
        if not all([to_addrs, subject, message]):
            messagebox.showwarning("Incomplete", "Please fill To, Subject, and Message fields.")
            return
        to_addrs_list = [addr.strip() for addr in to_addrs.split(",") if addr.strip()]
        if not to_addrs_list:
            messagebox.showwarning("Invalid Recipient", "Please enter at least one valid email address.")
            return
        
        self.is_sending = True
        self._set_send_state(True)
        print("[LOG] Starting send email background thread...")
        threading.Thread(target=self._perform_send, args=(to_addrs_list, subject, message), daemon=True).start()

    def _perform_send(self, to_addrs_list, subject, message):
        print("[LOG] Send thread started.")
        total_send_start = time.monotonic()
        try:
            self.after(0, lambda: self._show_send_status("🔐 Encrypting message...", 20))
            uuid = get_latest_valid_uuid()
            key = get_key_by_uuid(uuid)
            
            encryption_start = time.monotonic()
            encrypted_uuid = encrypt_message(uuid, key)
            encrypted_message = encrypt_message(message, key)
            combined_encrypted = f"{encrypted_uuid}:::{encrypted_message}"
            
            encrypted_attachments = []
            total_original_attach_size = 0
            total_encrypted_attach_size = 0
            if self.attach_enc:
                for filepath in self.attach_enc:
                    total_original_attach_size += os.path.getsize(filepath)
                    enc_b64, enc_filename = encrypt_file_to_base64(filepath, key)
                    total_encrypted_attach_size += len(enc_b64)
                    encrypted_attachments.append({"filename": enc_filename, "content": enc_b64})
            
            encryption_end = time.monotonic()
            self.performance_data["Last Encryption Time (s)"] = f"{encryption_end - encryption_start:.4f}"
            
            original_msg_size = len(message.encode('utf-8'))
            encrypted_msg_size = len(combined_encrypted)
            self.performance_data["Message Overhead Ratio"] = f"{encrypted_msg_size / original_msg_size:.2f}x" if original_msg_size > 0 else "N/A"
            if total_original_attach_size > 0:
                self.performance_data["Attachment Overhead Ratio"] = f"{total_encrypted_attach_size / total_original_attach_size:.2f}x"

            self.after(0, lambda: self._show_send_status("📤 Sending email...", 70))
            for to_addr in to_addrs_list:
                self.client.send_email(
                    self.email_id.get(), self.password.get(),
                    to_addr, subject, combined_encrypted,
                    self.attach_plain, encrypted_attachments
                )
            
            self.after(0, lambda: self._show_send_status("✅ Email sent successfully!", 100))
            time.sleep(1)
            self.after(0, self._send_success)
        except Exception as e:
            print(f"[ERROR] Exception in send thread: {e}")
            self.after(0, lambda msg=str(e): self._send_failed(msg))
        finally:
            total_send_end = time.monotonic()
            self.performance_data["Last Send Time (s)"] = f"{total_send_end - total_send_start:.4f}"
            self.after(0, self._update_diagnostics_display)

    def _send_success(self):
        print("[LOG] Send successful. Clearing form and updating GUI.")
        self.is_sending = False
        self._set_send_state(False)
        self.to_entry.delete(0, "end"); self.subject_entry.delete(0, "end")
        self.message_text.delete("1.0", "end")
        self.attach_plain.clear(); self.attach_enc.clear()
        self._update_attachment_label()
        self._show_status("✅ Email sent successfully!", "success")

    def _send_failed(self, error_msg):
        print(f"[LOG] Send failed. Updating GUI with error: {error_msg}")
        self.is_sending = False
        self._set_send_state(False)
        self._show_status("❌ Failed to send email", "error")
        messagebox.showerror("Send Failed", f"Failed to send email:\n\n{error_msg}")

    def _set_send_state(self, sending):
        self.send_btn.config(state="disabled" if sending else "normal")
        self.send_btn.config(text="📤 Sending..." if sending else "📤 Send Encrypted Email")
        self._toggle_spinner(self.send_spinner, sending)
        if sending:
            self.send_progress.pack(side="left", padx=5)
            self.send_status_label.pack(side="left", padx=5)
        else:
            self.send_progress.pack_forget()
            self.send_status_label.pack_forget()

    def _show_send_status(self, message, progress):
        self.send_status_label.config(text=message)
        self.send_progress.config(value=progress)

    def _initiate_fetch(self):
        print("[LOG] Fetch emails process initiated by user.")
        if self.is_fetching: return
        self.is_fetching = True
        self._set_fetch_state(True)
        print("[LOG] Starting fetch emails background thread...")
        threading.Thread(target=self._perform_fetch, daemon=True).start()

    def _perform_fetch(self):
        print("[LOG] Fetch thread started.")
        fetch_start = time.monotonic()
        try:
            self.after(0, lambda: self._show_fetch_status("📥 Downloading emails..."))
            messages = self.client.fetch_emails(self.email_id.get(), self.password.get(), count=20)
            self.after(0, lambda: self._fetch_success(messages))
        except Exception as e:
            print(f"[ERROR] Exception in fetch thread: {e}")
            self.after(0, lambda msg=str(e): self._fetch_failed(msg))
        finally:
            fetch_end = time.monotonic()
            self.performance_data["Last Fetch Time (s)"] = f"{fetch_end - fetch_start:.4f}"
            self.after(0, self._update_diagnostics_display)

    def _fetch_success(self, messages):
        print(f"[LOG] Fetch successful. Populating listbox with {len(messages)} messages.")
        self.is_fetching = False
        self._set_fetch_state(False)
        self.messages = messages
        self.email_listbox.delete(0, "end")
        for i, msg in enumerate(messages):
            sender_clean = email.utils.parseaddr(msg['sender'])[1] or msg['sender']
            display_text = f"📧 {msg['subject']} - {sender_clean}"
            if msg.get('attachments'):
                display_text += " 📎"
            self.email_listbox.insert(i, display_text)
        self._show_status(f"✅ Fetched {len(messages)} messages", "success")

    def _fetch_failed(self, error_msg):
        print(f"[LOG] Fetch failed. Updating GUI with error: {error_msg}")
        self.is_fetching = False
        self._set_fetch_state(False)
        self._show_fetch_status(f"❌ Fetch failed")
        self._show_status("❌ Failed to fetch emails", "error")
        messagebox.showerror("Fetch Failed", f"Could not retrieve emails:\n\n{error_msg}")

    def _set_fetch_state(self, fetching):
        self.fetch_btn.config(state="disabled" if fetching else "normal")
        self.fetch_btn.config(text="📥 Fetching..." if fetching else "📥 Fetch Emails")
        self._toggle_spinner(self.fetch_spinner, fetching)

    def _show_fetch_status(self, message):
        self.fetch_status_label.config(text=message)

    def _add_attachment(self):
        files = filedialog.askopenfilenames(title="Select files to attach")
        if files:
            print(f"[LOG] User attached {len(files)} plain file(s).")
            self.attach_plain.extend(files)
            self._update_attachment_label()

    def _add_encrypted_attachment(self):
        files = filedialog.askopenfilenames(title="Select files to encrypt and attach")
        if files:
            print(f"[LOG] User attached {len(files)} file(s) to be encrypted.")
            self.attach_enc.extend(files)
            self._update_attachment_label()

    def _update_attachment_label(self):
        total = len(self.attach_plain) + len(self.attach_enc)
        if total > 0:
            print(f"[LOG] Updating attachment label. Plain: {len(self.attach_plain)}, Encrypted: {len(self.attach_enc)}")
        self.attachment_label.config(text=f"{total} file{'s' if total != 1 else ''} attached" if total > 0 else "No attachments")

    def _show_email(self, event):
        selection = self.email_listbox.curselection()
        if not selection: return
        
        index = selection[0]
        msg = self.messages[index]
        encrypted_body = msg["body"]
        decrypted_body = ""
        self._last_decryption_uuid = None
        
        decryption_start = time.monotonic()
        try:
            if ":::" in encrypted_body:
                encrypted_uuid_b64, encrypted_message_b64 = encrypted_body.split(":::", 1)
                for candidate_uuid in list_all_valid_uuids():
                    try:
                        candidate_key = get_key_by_uuid(candidate_uuid)
                        decrypted_uuid = decrypt_message(encrypted_uuid_b64, candidate_key)
                        final_key = get_key_by_uuid(decrypted_uuid)
                        decrypted_body = decrypt_message(encrypted_message_b64, final_key)
                        self._last_decryption_uuid = decrypted_uuid
                        break 
                    except Exception:
                        continue
                else:
                     decrypted_body = f"[❌ DECRYPTION FAILED]\nError: No valid key found."
            else:
                decrypted_body = encrypted_body
        except Exception as e:
            decrypted_body = f"[❌ DECRYPTION FAILED]\nError: {e}"
        finally:
            decryption_end = time.monotonic()
            if ":::" in encrypted_body:
                self.performance_data["Last Decryption Time (s)"] = f"{decryption_end - decryption_start:.4f}"
                self.after(0, self._update_diagnostics_display)

        sender_clean = email.utils.parseaddr(msg['sender'])[1] or msg['sender']
        display_text = f"📧 From: {sender_clean}\n📝 Subject: {msg['subject']}\n"
        if msg.get('attachments'):
            display_text += f"📎 Attachments: {len(msg['attachments'])} file(s)\n"
        display_text += f"\n{'='*50}\n\n{decrypted_body}"
        
        self.email_display.config(state="normal")
        self.email_display.delete("1.0", "end")
        self.email_display.insert("1.0", display_text)
        self.email_display.config(state="disabled")

    def _save_attachments(self):
        print("[LOG] Save attachments initiated by user.")
        selection = self.email_listbox.curselection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select an email first.")
            return

        msg = self.messages[selection[0]]
        if not msg.get("attachments"):
            messagebox.showinfo("No Attachments", "Selected email has no attachments.")
            return

        uuid = getattr(self, "_last_decryption_uuid", None)
        if not uuid:
            messagebox.showerror("Decryption Key Unknown", "Cannot save attachments. Please select and view an encrypted email first to establish the decryption key.")
            return
        
        print(f"[LOG] Using master UUID {uuid} to decrypt and save attachments.")
        key = get_key_by_uuid(uuid)
        
        save_dir = filedialog.askdirectory(title="Select folder to save attachments")
        if not save_dir:
            print("[LOG] User cancelled save dialog.")
            return
        print(f"[LOG] User selected directory to save attachments: {save_dir}")

        try:
            for attachment in msg["attachments"]:
                filename = attachment["filename"]
                filepath = os.path.join(save_dir, filename)
                if filename.endswith(".enc"):
                    print(f"[LOG] Decrypting and saving encrypted attachment: {filename}")
                    output_path = filepath[:-4]
                    decrypt_file_from_base64(attachment["content"], key, output_path)
                else:
                    print(f"[LOG] Saving plain attachment: {filename}")
                    with open(filepath, "wb") as f:
                        f.write(base64.b64decode(attachment["content"]))
            messagebox.showinfo("Success", f"Saved {len(msg['attachments'])} attachment(s) to:\n{save_dir}")
            print(f"[LOG] Successfully saved {len(msg['attachments'])} attachment(s).")
        except Exception as e:
            print(f"[ERROR] Failed during attachment saving: {e}")
            messagebox.showerror("Save Error", f"Failed to save an attachment:\n{e}")
            return

    def _show_status(self, message, status_type="info"):
        colors = {"info": "blue", "success": "green", "error": "red"}
        self.status_label.config(text=message, foreground=colors.get(status_type, "black"))

def main():
    print("Starting Secure QKD Email Client...")
    try:
        app = SecureQKDEmailGUI()
        app.mainloop()
    except Exception as e:
        print(f"Application error: {e}")
        messagebox.showerror("Application Error", f"A fatal error occurred:\n{e}")

if __name__ == "__main__":
    main()