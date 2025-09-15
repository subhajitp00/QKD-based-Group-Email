#!/usr/bin/env python3
"""
Working and Corrected Mail Utilities for QKD Email Client
Handles SMTP/IMAP operations for Zoho India and Gmail India
"""

import base64
import os
import ssl
import smtplib
import imaplib
import email
import mimetypes
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

class EmailClient:
    """
    Email client supporting Zoho India and Gmail India.
    Handles sending and receiving with regular and encrypted attachments.
    """
    def __init__(self, provider="Zoho India"):
        self.provider = provider.lower()
        if "gmail" in self.provider:
            self.smtp_host, self.smtp_port = "smtp.gmail.com", 587
            self.imap_host, self.imap_port = "imap.gmail.com", 993
        else: # Default to Zoho India
            self.smtp_host, self.smtp_port = "smtp.zoho.in", 587
            self.imap_host, self.imap_port = "imap.zoho.in", 993
        print(f"[LOG] EmailClient initialized for provider: {provider}. SMTP: {self.smtp_host}, IMAP: {self.imap_host}")

    def send_email(self, user_email, password, to_address, subject, body,
                   attachments=None, encrypted_attachments=None):
        """
        Sends an email with support for regular and pre-encrypted attachments.
        """
        print(f"\n[LOG] === Preparing to send email ===")
        print(f"[LOG] From: {user_email}, To: {to_address}, Subject: {subject}")
        print(f"[LOG] Plain attachments: {len(attachments or [])}, Encrypted attachments: {len(encrypted_attachments or [])}")
        
        message = MIMEMultipart()
        message["From"] = user_email
        message["To"] = to_address
        message["Subject"] = subject
        print("[LOG] Attaching main message body.")
        message.attach(MIMEText(body, "plain"))

        if attachments:
            print("[LOG] Processing regular attachments...")
            for file_path in attachments:
                self._attach_regular_file(message, file_path)
        
        if encrypted_attachments:
            print("[LOG] Processing pre-encrypted attachments...")
            for attachment_data in encrypted_attachments:
                self._attach_pre_encrypted_data(message, attachment_data)
        
        self._send_via_smtp(user_email, password, to_address, message)
        print("[LOG] SUCCESS: Email sending process completed successfully!")
        return True

    def _send_via_smtp(self, user_email, password, to_address, message):
        """Connects to SMTP server and sends the message."""
        print(f"[LOG] Connecting to SMTP server: {self.smtp_host}:{self.smtp_port}")
        context = ssl.create_default_context()
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.set_debuglevel(0)
                print("[LOG] SMTP connection established. Starting TLS...")
                server.starttls(context=context)
                print("[LOG] TLS started. Logging in...")
                server.login(user_email, password)
                print(f"[LOG] Login successful for {user_email}. Sending email...")
                server.sendmail(user_email, [to_address], message.as_string())
                print("[LOG] sendmail command issued.")
        except smtplib.SMTPAuthenticationError as e:
            error_msg = f"Authentication failed: {e}. For Gmail, use an App Password."
            print(f"[ERROR] {error_msg}")
            raise Exception(error_msg)
        except Exception as e:
            error_msg = f"Send failed: {str(e)}"
            print(f"[ERROR] {error_msg}")
            raise Exception(error_msg)

    def _attach_regular_file(self, message, file_path):
        """Attaches a regular (unencrypted) file to the email message."""
        print(f"[LOG] Attaching regular file: {file_path}")
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            filename = os.path.basename(file_path)
            ctype, encoding = mimetypes.guess_type(file_path)
            if ctype is None or encoding is not None:
                ctype = "application/octet-stream"
            maintype, subtype = ctype.split("/", 1)
            print(f"[LOG] Detected MIME type for {filename}: {ctype}")
            
            with open(file_path, "rb") as f:
                part = MIMEBase(maintype, subtype)
                part.set_payload(f.read())
            
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
            message.attach(part)
            print(f"[LOG] Successfully attached regular file: {filename}")
        except Exception as e:
            print(f"[ERROR] Failed to attach regular file {file_path}: {e}")
            raise

    def _attach_pre_encrypted_data(self, message, attachment_data):
        """
        Attaches a pre-encrypted, base64-encoded file from a dictionary.
        """
        filename = attachment_data.get("filename", "unknown.enc")
        print(f"[LOG] Attaching pre-encrypted data as: {filename}")
        try:
            b64_content = attachment_data["content"]
            part = MIMEBase("application", "octet-stream")
            part.set_payload(base64.b64decode(b64_content))
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
            message.attach(part)
            print(f"[LOG] Successfully attached pre-encrypted data: {filename}")
        except Exception as e:
            print(f"[ERROR] Failed to attach pre-encrypted data for {filename}: {e}")
            raise

    def fetch_emails(self, user_email, password, count=10):
        """Fetches recent emails from the inbox."""
        print(f"\n[LOG] === Starting email fetch for {user_email} ===")
        try:
            print(f"[LOG] Connecting to IMAP server: {self.imap_host}:{self.imap_port}")
            mail = imaplib.IMAP4_SSL(self.imap_host, self.imap_port)
            print("[LOG] IMAP connection established. Logging in...")
            mail.login(user_email, password)
            print("[LOG] IMAP login successful. Selecting 'inbox'...")
            mail.select("inbox")
            
            print("[LOG] Searching for all emails...")
            result, data = mail.search(None, "ALL")
            if result != 'OK':
                raise Exception("Failed to search emails")
                
            email_ids = data[0].split()
            print(f"[LOG] Found {len(email_ids)} total emails. Fetching the latest {count}.")
            recent_ids = reversed(email_ids[-count:])
            
            messages = []
            for email_id in recent_ids:
                try:
                    email_id_str = email_id.decode()
                    print(f"[LOG] Fetching email with ID: {email_id_str}")
                    res, msg_data = mail.fetch(email_id, "(RFC822)")
                    if res != 'OK':
                        print(f"[WARNING] Could not fetch email ID {email_id_str}")
                        continue
                    
                    raw_email = msg_data[0][1]
                    email_message = email.message_from_bytes(raw_email)
                    
                    subject = email_message.get("subject", "No Subject")
                    sender = email_message.get("from", "Unknown Sender")
                    print(f"[LOG] Parsing email from '{sender}' with subject '{subject}'")
                    
                    body, attachments = self._extract_email_content(email_message)
                    
                    messages.append({
                        "subject": subject, "sender": sender,
                        "body": body, "attachments": attachments
                    })
                    print(f"[LOG] Successfully parsed email ID {email_id_str}.")
                except Exception as e:
                    print(f"[WARNING] Failed to parse email {email_id.decode()}: {e}")
            
            print("[LOG] Logging out from IMAP server.")
            mail.logout()
            print(f"[LOG] SUCCESS: Email fetching process completed. Fetched {len(messages)} emails.")
            return messages
        except Exception as e:
            error_msg = f"Fetch failed: {str(e)}"
            print(f"[ERROR] {error_msg}")
            raise Exception(error_msg)

    def _extract_email_content(self, email_message):
        """Extracts body text and attachments from an email message."""
        body, attachments = "", []
        try:
            if email_message.is_multipart():
                for part in email_message.walk():
                    ctype = part.get_content_type()
                    cdisp = str(part.get("Content-Disposition"))

                    if ctype == "text/plain" and "attachment" not in cdisp:
                        if not body:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body = payload.decode("utf-8", errors="ignore")
                    elif "attachment" in cdisp:
                        filename = part.get_filename()
                        if filename:
                            content = part.get_payload(decode=True)
                            if content:
                                attachments.append({
                                    "filename": filename,
                                    "content": base64.b64encode(content).decode('utf-8'),
                                    "content_type": ctype
                                })
            else:
                payload = email_message.get_payload(decode=True)
                if payload:
                    body = payload.decode("utf-8", errors="ignore")
        except Exception as e:
            body = f"Error extracting email content: {str(e)}"
            print(f"[ERROR] {body}")
        return body, attachments