import os
print("DB Absolute Path in use:", os.path.abspath("instance/scan_records.db"))
print("Instance folder exists:", os.path.isdir("instance"))
print("File exists:", os.path.isfile("instance/scan_records.db"))
import os.path
import pickle
import base64
import time
import requests
import re
import datetime

from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.mime.text import MIMEText

# === Database logging dependencies ===
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Float, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class ScanRecord(Base):
    __tablename__ = 'scan_record'
    id = Column(Integer, primary_key=True, autoincrement=True)
    sender = Column(String(255))
    subject = Column(String(500))
    scanned_at = Column(DateTime, default=datetime.datetime.utcnow)
    is_phishing = Column(Boolean)
    threat_score = Column(Float)
    recommendations = Column(Text)
    deleted = Column(Boolean, default=False)

engine = create_engine('sqlite:///scan_records.db')
Session = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

def log_scan_result(sender, subject, is_phishing, threat_score=None, recommendations=None):
    session = Session()
    scan = ScanRecord(
        sender=sender,
        subject=subject,
        scanned_at=datetime.datetime.utcnow(),
        is_phishing=is_phishing,
        threat_score=threat_score,
        recommendations="\n".join(recommendations) if recommendations else "",
        deleted=False  # Always log as not deleted from watcher
    )
    session.add(scan)
    session.commit()
    print(f"LOGGED TO DB: {sender} | {subject} | Phishing? {is_phishing} | Score: {threat_score}")
    session.close()

# === Gmail and phishing config ===

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
]

DETECTOR_API_URL = "http://localhost:5000/api/analyze"
NOTIFY_EMAIL = "yourmail@example.com"

NO_REPLY_LIST = [
    'noreply', 'no-reply', 'donotreply', 'do-not-reply', 'notification', 'notifications',
    'mailer-daemon', 'automated', 'auto', 'autoresponder', 'auto-reply', 'auto_response',
    'system', 'robot', 'postmaster', 'bounce', 'bounces', 'nobody', 'no_reply', 'noreplies',
    'alerts', 'alert', 'announce', 'announcement', 'update', 'updates', 'support', 'helpdesk',
    'info', 'information', 'service', 'admin', 'administrator', 'do_not_reply', 'please_do_not_reply',
    'replyto', 'reply_to', 'unsubscribe', 'events', 'request', 'ticket', 'invoice', 'billing',
    'receipt', 'order', 'sales', 'accounts', 'account', 'customerservice', 'customersupport',
    'contactus', 'team', 'survey', 'bulkmail', 'reminder', 'reminders', 'scheduled', 'listserv',
    'marketing', 'optout', 'opt-out', 'feedback', 'confirm', 'confirmation', 'passwordreset',
    'reset', 'verif', 'verification', 'norespond', 'no_response'
]

TRUSTED_DOMAINS = [
    "youtube.com", "youtu.be", "google.com", "gmail.com", "outlook.com",
    "microsoft.com", "apple.com", "icloud.com", "amazon.com", "ebay.com",
    "paypal.com", "linkedin.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "reddit.com", "github.com", "stackoverflow.com",
    "wikipedia.org", "nytimes.com", "bbc.com", "cnn.com", "wsj.com",
    "slack.com", "zoom.us", "dropbox.com", "box.com", "drive.google.com",
    "docs.google.com", "medium.com", "office.com", "live.com", "aol.com",
    "protonmail.com", "duckduckgo.com", "quora.com", "netflix.com", "hulu.com",
    "disneyplus.com", "hotstar.com", "spotify.com", "adobe.com", "xda-developers.com",
    "wordpress.com", "blogger.com", "skype.com", "twitch.tv", "roblox.com",
    "steamcommunity.com", "steampowered.com", "oracle.com", "ibm.com", "intel.com",
    "phillips.com", "samsung.com", "sony.com", "lg.com", "dell.com", "hp.com",
    "lenovo.com", "asus.com", "nvidia.com", "amd.com", "uber.com", "airbnb.com",
    "booking.com", "expedia.com", "trivago.com", "makemytrip.com", "tripadvisor.com",
    "zomato.com", "swiggy.com", "flipkart.com", "snapdeal.com", "bigbasket.com",
    "whatsapp.com", "telegram.org", "signal.org", "tumblr.com", "flickr.com",
    "pinterest.com", "imgur.com", "canva.com", "coursera.org", "udemy.com",
    "edx.org", "khanacademy.org", "tiktok.com", "vimeo.com", "jiomart.com",
    "petrolpump.com", "openai.com", "bard.google.com", "huggingface.co",
    "medium.com", "bitbucket.org"
]

def extract_urls(text):
    url_pattern = r'https?://[^\s<>()"]+'
    return re.findall(url_pattern, text)

def is_trusted_url(url):
    for domain in TRUSTED_DOMAINS:
        if domain.lower() in url.lower():
            return True
    return False

def all_urls_trusted(body):
    urls = extract_urls(body)
    if not urls:
        return True
    return all(is_trusted_url(url) for url in urls)

def gmail_authenticate():
    creds = None
    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)
    return build("gmail", "v1", credentials=creds)

def list_unread_messages(service):
    try:
        results = service.users().messages().list(userId="me", labelIds=["INBOX", "UNREAD"]).execute()
        return results.get("messages", [])
    except HttpError as error:
        print(f"An error occurred: {error}")
        return []

def get_email_content(service, msg_id):
    msg = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
    headers = msg["payload"].get("headers", [])
    subject = next((h["value"] for h in headers if h["name"] == "Subject"), "")
    sender = next((h["value"] for h in headers if h["name"] == "From"), "")
    parts = msg["payload"].get("parts", [])
    body = ""
    for part in parts:
        if part["mimeType"] == "text/plain":
            body_data = part["body"].get("data")
            if body_data:
                body = base64.urlsafe_b64decode(body_data).decode("utf-8", errors="replace")
                break
    return subject, sender, body

def skip_sender(sender):
    sender = sender.lower()
    return any(bad in sender for bad in NO_REPLY_LIST)

def analyze_email(subject, sender, body):
    data = {
        "subject": subject,
        "sender": sender,
        "email_text": body,
    }
    try:
        response = requests.post(DETECTOR_API_URL, json=data, timeout=30)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error analyzing email: {response.text}")
            return None
    except Exception as e:
        print(f"Error connecting to detection API: {str(e)}")
        return None

def add_result_label(service, msg_id, is_phishing):
    label_name = "PhishScanAI-Phishing" if is_phishing else "PhishScanAI-Safe"
    labels = service.users().labels().list(userId='me').execute().get('labels', [])
    label_id = None
    for lbl in labels:
        if lbl['name'] == label_name:
            label_id = lbl['id']
            break
    if not label_id:
        label_obj = {'name': label_name, 'labelListVisibility': 'labelShow', 'messageListVisibility': 'show'}
        label = service.users().labels().create(userId='me', body=label_obj).execute()
        label_id = label['id']
    try:
        service.users().messages().modify(userId="me", id=msg_id, body={"addLabelIds": [label_id]}).execute()
    except HttpError as error:
        print(f"Could not label message {msg_id}: {error}")

def send_report(service, to_email, subject, body_text):
    message = MIMEText(body_text)
    message["to"] = to_email
    message["from"] = "me"
    message["subject"] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    message_body = {"raw": raw_message}
    try:
        sent_msg = service.users().messages().send(userId="me", body=message_body).execute()
        print(f"Notification email sent to {to_email}: Message Id: {sent_msg['id']}")
    except HttpError as error:
        print(f"An error occurred sending notification: {error}")

def main():
    service = gmail_authenticate()
    print("Gmail authentication successful. Monitoring inbox...")
    while True:
        messages = list_unread_messages(service)
        if not messages:
            print("No new messages. Waiting...")
        for msg in messages:
            subject, sender, body = get_email_content(service, msg["id"])
            print(f"Analyzing email from: {sender} | Subject: {subject}")
            if skip_sender(sender):
                print(f"Skipping system/notifier: {sender}")
                add_result_label(service, msg["id"], False)
                log_scan_result(sender, subject, False, None, ["Skipped system email"])
                continue
            result = analyze_email(subject, sender, body)
            is_phishing = result.get("is_phishing") if result else False
            # TRUSTED DOMAIN FILTER
            if is_phishing:
                if all_urls_trusted(body):
                    print(" - Skipped phishing flag: All URLs are on trusted domains")
                    is_phishing = False
            if is_phishing:
                report_body = (
                    f"Phishing detected!\n\n"
                    f"Subject: {subject}\nSender: {sender}\nThreat Score: {result['threat_score']}%\n"
                    f"Recommendations:\n- " + "\n- ".join(result["recommendations"])
                )
                send_report(service, NOTIFY_EMAIL, "Phishing Alert: Suspicious Email Detected", report_body)
            add_result_label(service, msg["id"], is_phishing)
            log_scan_result(
                sender=sender,
                subject=subject,
                is_phishing=is_phishing,
                threat_score=result.get('threat_score') if result else None,
                recommendations=result.get('recommendations') if result else None
            )
        time.sleep(300)  # Scan every 5 minutes

if __name__ == "__main__":
    main()