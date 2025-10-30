import os
print("DB Absolute Path in use:", os.path.abspath("instance/scan_records.db"))
print("Instance folder exists:", os.path.isdir("instance"))
print("File exists:", os.path.isfile("instance/scan_records.db"))
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, make_response, session
from flask_cors import CORS
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import re
from dotenv import load_dotenv
import validators
from flask_sqlalchemy import SQLAlchemy

load_dotenv()

app = Flask(__name__)
app.secret_key = 'your-super-secret-key'  # Needed for flash/session!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scan_records.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
CORS(app)
db = SQLAlchemy(app)

class ScanRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(255))
    subject = db.Column(db.String(500))
    scanned_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    is_phishing = db.Column(db.Boolean, default=False)
    threat_score = db.Column(db.Float)
    recommendations = db.Column(db.Text)
    deleted = db.Column(db.Boolean, default=False)
    def __repr__(self):
        return f"<ScanRecord {self.subject}>"

MODEL_NAME = "ealvaradob/bert-finetuned-phishing"
print("Loading BERT model... (first time takes ~1 minute)")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
model.eval()
print("✓ Model loaded!")

def extract_urls(text):
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text)

def analyze_email_text(email_text):
    inputs = tokenizer(
        email_text,
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding=True
    )
    with torch.no_grad():
        outputs = model(**inputs)
        probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
    phishing_prob = probabilities[0][1].item()
    return {
        "phishing_probability": round(phishing_prob * 100, 2),
        "is_phishing": phishing_prob > 0.5,
        "confidence": round(max(probabilities[0].tolist()) * 100, 2)
    }

def extract_suspicious_keywords(text):
    keywords = [
        'urgent', 'verify', 'suspend', 'limited time', 'act now',
        'confirm account', 'unusual activity', 'click here',
        'password', 'bank account', 'credit card',
        'winner', 'congratulations', 'claim', 'prize',
        'inheritance', 'wire transfer'
    ]
    found = []
    text_lower = text.lower()
    for kw in keywords:
        if kw in text_lower:
            found.append(kw)
    return found

def analyze_url(url):
    result = {"url": url, "is_malicious": False, "risk_score": 0, "issues": []}
    if not validators.url(url):
        result["issues"].append("Invalid URL format")
        result["risk_score"] = 30
        return result
    url_lower = url.lower()
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        result["issues"].append("Uses IP address")
        result["risk_score"] += 30
    suspicious = ['verify', 'account', 'secure', 'login', 'update', 'password']
    if any(s in url_lower for s in suspicious):
        result["issues"].append("Suspicious keywords")
        result["risk_score"] += 20
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly']
    if any(s in url_lower for s in shorteners):
        result["issues"].append("URL shortener detected")
        result["risk_score"] += 15
    if '@' in url:
        result["issues"].append("Contains @ symbol")
        result["risk_score"] += 40
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
    if any(url_lower.endswith(tld) for tld in suspicious_tlds):
        result["issues"].append("Suspicious TLD")
        result["risk_score"] += 25
    result["is_malicious"] = result["risk_score"] >= 50
    result["risk_score"] = min(100, result["risk_score"])
    return result

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "message": "Phishing Detector ready"})

@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        if not data or 'email_text' not in data:
            return jsonify({"error": "email_text required"}), 400
        email_text = data['email_text']
        subject = data.get('subject', '')
        sender = data.get('sender', '')
        full_text = f"{subject} {email_text}"
        text_analysis = analyze_email_text(full_text)
        urls = extract_urls(email_text)
        url_analysis = [analyze_url(url) for url in urls[:5]]
        keywords = extract_suspicious_keywords(full_text)
        threat_score = text_analysis['phishing_probability']
        if url_analysis:
            malicious_count = sum(1 for u in url_analysis if u['is_malicious'])
            threat_score = min(100, threat_score + (malicious_count * 20))
        if len(keywords) > 3:
            threat_score = min(100, threat_score + 10)
        if threat_score >= 75:
            threat_level, color = "CRITICAL", "red"
        elif threat_score >= 50:
            threat_level, color = "HIGH", "orange"
        elif threat_score >= 25:
            threat_level, color = "MEDIUM", "yellow"
        else:
            threat_level, color = "LOW", "green"
        recommendations = []
        if threat_level in ["CRITICAL", "HIGH"]:
            recommendations = [
                "⚠️ DO NOT click any links",
                "⚠️ DO NOT provide personal info",
                "🗑️ Delete immediately",
                "📧 Report as phishing"
            ]
        elif threat_level == "MEDIUM":
            recommendations = [
                "⚡ Exercise caution",
                "🔍 Verify sender carefully"
            ]
        else:
            recommendations = ["✅ Email appears legitimate"]
        if keywords:
            recommendations.append(f"⚠️ Found {len(keywords)} suspicious keyword(s)")
        scan = ScanRecord(
            sender=sender,
            subject=subject,
            is_phishing=threat_score >= 50,
            threat_score=threat_score,
            recommendations="\n".join(recommendations)
        )
        db.session.add(scan)
        db.session.commit()
        return jsonify({
            "threat_score": round(threat_score, 2),
            "threat_level": threat_level,
            "color": color,
            "is_phishing": threat_score >= 50,
            "analysis": {
                "text_analysis": text_analysis,
                "urls_found": len(urls),
                "url_analysis": url_analysis,
                "suspicious_keywords": keywords,
                "sender": sender
            },
            "recommendations": recommendations
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scan-history')
def scan_history():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str)
    filter_phish = request.args.get('filter_phish', 'all', type=str)
    since = request.args.get('since', '', type=str)
    query = ScanRecord.query.filter_by(deleted=False)
    if search:
        query = query.filter(
            (ScanRecord.sender.ilike(f'%{search}%')) | (ScanRecord.subject.ilike(f'%{search}%'))
        )
    if filter_phish == 'phishing':
        query = query.filter_by(is_phishing=True)
    elif filter_phish == 'safe':
        query = query.filter_by(is_phishing=False)
    if since:
        now = datetime.utcnow()
        if since == '1hr':
            query = query.filter(ScanRecord.scanned_at >= now - timedelta(hours=1))
        elif since == '24hr':
            query = query.filter(ScanRecord.scanned_at >= now - timedelta(hours=24))
        elif since == '7day':
            query = query.filter(ScanRecord.scanned_at >= now - timedelta(days=7))
    records = query.order_by(ScanRecord.scanned_at.desc()).paginate(page=page, per_page=10, error_out=False)
    deleted_id = session.pop('deleted_id', None)
    return render_template('index.html', records=records, search=search, filter_phish=filter_phish, since=since, deleted_id=deleted_id)

@app.route('/export')
def export_csv():
    import csv
    from io import StringIO
    si = StringIO()
    cw = csv.writer(si)
    records = ScanRecord.query.filter_by(deleted=False).all()
    cw.writerow(['Sender', 'Subject', 'Scanned At', 'Is Phishing', 'Threat Score', 'Recommendations'])
    for r in records:
        cw.writerow([r.sender, r.subject, r.scanned_at, r.is_phishing, r.threat_score, r.recommendations])
    output = si.getvalue()
    response = make_response(output)
    response.headers["Content-Disposition"] = "attachment; filename=scan_report.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    scan = ScanRecord.query.get_or_404(scan_id)
    scan.deleted = True
    db.session.commit()
    session['deleted_id'] = scan_id
    flash("Deleted. You can undo.", "warning")
    return redirect(request.referrer or url_for('scan_history'))

@app.route('/undo-delete/<int:scan_id>', methods=['POST'])
def undo_delete(scan_id):
    scan = ScanRecord.query.get_or_404(scan_id)
    scan.deleted = False
    db.session.commit()
    flash("Restored!", "success")
    return redirect(request.referrer or url_for('scan_history'))

@app.route('/api/test-samples', methods=['GET'])
def test_samples():
    samples = [
        {
            "id": 1,
            "subject": "URGENT: Verify your account immediately",
            "sender": "security@paypa1-verify.com",
            "body": "Your PayPal account has been limited. Click here to verify: [http://paypa1-verify.com/secure](http://paypa1-verify.com/secure). Verify within 24 hours or lose access.",
            "label": "phishing"
        },
        {
            "id": 2,
            "subject": "Your Amazon order #123-4567890",
            "sender": "auto-confirm@amazon.com",
            "body": "Hello, Your order has shipped! Track it: [https://amazon.com/track/xyz](https://amazon.com/track/xyz). Thank you!",
            "label": "legitimate"
        },
        {
            "id": 3,
            "subject": "You won $1,000,000!",
            "sender": "lottery@prize-winner.tk",
            "body": "CONGRATULATIONS! You won! Claim your prize: wire bank details and social security number now!",
            "label": "phishing"
        }
    ]
    return jsonify(samples)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("\n" + "="*50)
    print("PhishShield AI - Running on http://localhost:5000")
    print("Open /scan-history in your browser")
    print("="*50 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)