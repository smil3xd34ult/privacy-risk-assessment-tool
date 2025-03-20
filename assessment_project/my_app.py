from flask import Flask, request, render_template, redirect, url_for, session, jsonify, flash
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from email.mime.text import MIMEText
from datetime import datetime, timezone, timedelta
from itsdangerous import URLSafeTimedSerializer
from pymongo import MongoClient
from functools import wraps
import smtplib
import requests
import random
import uuid

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/privacy_assessment"
app.config["SECRET_KEY"] = "your_secret_key"
mongo = PyMongo(app)
ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# API Keys
MOZILLA_OBSERVATORY_API = "https://http-observatory.security.mozilla.org/api/v1/analyze"

# Mailtrap SMTP Config
MAILTRAP_USERNAME = "12856b4a0a14bb"
MAILTRAP_PASSWORD = "da8c2b95c78e0e"
MAILTRAP_HOST = "smtp.mailtrap.io"
MAILTRAP_PORT = 2525

# Token serializer
ts = URLSafeTimedSerializer("your_secret_key")

# Function to generate OTP and expiry time
def generate_otp():
    otp = str(random.randint(100000, 999999))  # Generate a 6-digit OTP
    otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)  # Set expiry time to 10 minutes from now
    return otp, otp_expiry

def send_email(to_email, subject, message):
    msg = MIMEText(message, "html")
    msg["Subject"] = subject
    msg["From"] = "noreply@yourapp.com"
    msg["To"] = to_email
    
    with smtplib.SMTP(MAILTRAP_HOST, MAILTRAP_PORT) as server:
        server.login(MAILTRAP_USERNAME, MAILTRAP_PASSWORD)
        server.sendmail(msg["From"], [msg["To"]], msg.as_string())

# USER AUTHENTICATION
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form

        if mongo.db.users.find_one({"email": data["email"]}):
            flash("Email already exists", "error")
            return redirect(url_for('login'))
        otp, otp_expiry = generate_otp()  # Generate OTP and expiry time
        if data["password"] != data["confirm_password"]:
            flash("Passwords do not match", "error")
            return redirect(url_for('register'))

        # Generate OTP for first-time registration
        otp, otp_expiry = generate_otp()

        # Store temporary OTP in session instead of database
        session["pending_user"] = {
            "username": data["username"],
            "email": data["email"],
            "password": generate_password_hash(data["password"]),
            "otp": otp,
            "otp_expiry": otp_expiry.isoformat()  # Convert to string for session storage
        }

        # Send OTP Email
        send_email(data["email"], "Your OTP Code", f"Your OTP code is: <b>{otp}</b>. It expires in 10 minutes.")

        flash("Please verify your email using the OTP sent to your inbox.", "info")
        return redirect(url_for('verify_registration'))  # Redirect to OTP verification

    return render_template('register.html')

@app.route('/verify_registration', methods=['GET', 'POST'])
def verify_registration():
    if "pending_user" not in session:
        flash("Invalid request. Please register again.", "error")
        return redirect(url_for('register'))

    pending_user = session["pending_user"]

    if request.method == "POST":
        user_otp = request.form.get("email_code", "").strip()  # Fix field name

        if not user_otp:
            flash("Please enter the OTP.", "error")
            return redirect(url_for('verify_registration'))

        # Check if OTP exists
        if "otp_expiry" not in pending_user or "otp" not in pending_user:
            flash("Invalid OTP request. Please register again.", "error")
            session.pop("pending_user", None)
            return redirect(url_for('register'))

        # Convert expiry string back to datetime safely
        try:
            otp_expiry = datetime.fromisoformat(pending_user["otp_expiry"])
        except ValueError:
            flash("OTP expiration data is invalid. Please register again.", "error")
            session.pop("pending_user", None)
            return redirect(url_for('register'))

        # Validate OTP
        if user_otp != pending_user["otp"]:
            flash("Invalid OTP. Please try again.", "error")
            return redirect(url_for('verify_registration'))

        if datetime.now(timezone.utc) > otp_expiry:
            flash("OTP expired. Please register again.", "error")
            session.pop("pending_user", None)
            return redirect(url_for('register'))

        # Store user in database only after OTP verification
        mongo.db.users.insert_one({
            "username": pending_user["username"],
            "email": pending_user["email"],
            "password": pending_user["password"],
            "confirmed": True
        })

        session.pop("pending_user", None)  # Remove after storing

        flash("Email verified! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('verify_registration.html', email=pending_user["email"])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")

        user = mongo.db.users.find_one({"email": email})

        if not user:
            flash("Invalid email or password.", "error")
            return redirect(url_for('login'))

        if not check_password_hash(user["password"], password):
            flash("Invalid email or password.", "error")
            return redirect(url_for('login'))

        session["user"] = user["email"]
        flash("Login successful!", "success")
        return redirect(url_for('home'))  # Redirect to home if verified

    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get("email")
        user = mongo.db.users.find_one({"email": email})

        if not user:
            flash("No account found with this email.", "error")
            return redirect(url_for('forgot_password'))

        # Generate reset token
        token = ts.dumps(email, salt="password-reset")
        reset_url = url_for('reset_password', token=token, _external=True)

        # Send email
        send_email(email, "Reset Your Password", f"Click <a href='{reset_url}'>here</a> to reset your password.")

        flash("Password reset link sent to your email.", "success")
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = ts.loads(token, salt="password-reset", max_age=3600)  # Token valid for 1 hour
    except:
        flash("The password reset link is invalid or has expired.", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('reset_password', token=token))

        # Update password in the database
        hashed_password = generate_password_hash(new_password)
        mongo.db.users.update_one({"email": email}, {"$set": {"password": hashed_password}})

        flash("Your password has been reset! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    session.pop("user", None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))  # Redirects to login page

@app.route('/home')
def home():
    if "user" not in session:
        flash("You must be logged in to access this page.", "warning")
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({"email": session["user"]})
    if not user:
        flash("User not found.", "error")
        session.pop("user", None)  # Clear invalid session
        return redirect(url_for('login'))

    return render_template('home.html', current_user=user)  # Use current_user to match home.html

# MongoDB Connection
mongo = MongoClient("mongodb://localhost:27017/")["privacy_assessment"]

# CHECK SECURITY HEADERS
def check_security_headers(url):
    try:
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        api_url = f"https://securityheaders.com/?q={domain}&followRedirects=on"

        print(f"Security Headers API Request: {api_url}")  # Debugging

        return {"security_headers_report": api_url}  # Returns a direct report link
    except requests.exceptions.RequestException as e:
        return {"error": f"Security Headers API failed: {str(e)}"}
    
# DUCKDUCKGO API
def check_duckduckgo_trackers(url):
    try:
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        api_url = f"https://duckduckgo.com/?q=!privacy+{domain}&format=json"

        response = requests.get(api_url, timeout=10)
        print(f"DuckDuckGo Response: {response.status_code} - {response.text[:500]}")  # Show first 500 chars

        try:
            json_data = response.json()
            return {
                "trackers_found": json_data.get("trackers", []),
                "privacy_score": json_data.get("privacy_score", "No privacy data available"),
                "https_enforced": json_data.get("https", "Unknown")
            }
        except ValueError:
            return {"error": "DuckDuckGo returned an invalid response"}

    except requests.exceptions.RequestException as e:
        return {"error": f"DuckDuckGo request failed: {str(e)}"}
    
# GOOGLE SAFE BROWSING API  
def check_google_safe_browsing(url):
    api_key = "AIzaSyBzW-drlhXmZlWLyrR660KncNE5lmKoF-M"  # Replace with your actual API key
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

    payload = {
        "client": {
            "clientId": "privacy-scanner",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(api_url, json=payload, timeout=10)
        data = response.json()
        print(f"Google Safe Browsing Response: {response.status_code} - {data}")  # Debugging

        if "matches" in data:
            return {"risk": "High", "details": data["matches"]}
        return {"risk": "Low", "details": "No known threats"}

    except requests.exceptions.RequestException as e:
        return {"error": f"Google Safe Browsing API failed: {str(e)}"}

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    scan_id = str(uuid.uuid4())
    print(f" Starting scan for {url} (Scan ID: {scan_id})")

    # Call APIs
    security_headers_results = check_security_headers(url)
    duckduckgo_results = check_duckduckgo_trackers(url)
    google_safe_browsing_results = check_google_safe_browsing(url)

    # Generate Recommendations
    scan_results = {
        "security_headers_results": security_headers_results,
        "duckduckgo_results": duckduckgo_results,
        "google_safe_browsing_results": google_safe_browsing_results
    }
    recommendations = generate_recommendations(scan_results)

    # Check if all APIs failed
    status = "completed"
    if "error" in security_headers_results and "error" in duckduckgo_results and "error" in google_safe_browsing_results:
        status = "failed"

    # Create scan entry
    scan_entry = {
        "scan_id": scan_id,
        "target": url,
        "status": status,
        "security_headers_results": security_headers_results,
        "duckduckgo_results": duckduckgo_results,
        "google_safe_browsing_results": google_safe_browsing_results,
        "recommendations": recommendations,
        "timestamp": datetime.now(timezone.utc)
    }

    # Store scan results in MongoDB
    result = mongo.db.scans.insert_one(scan_entry)

    if result.inserted_id:
        print(f" Scan saved to MongoDB: {scan_entry}")
    else:
        print(f"ERROR: Scan NOT saved to MongoDB!")

    return jsonify(scan_entry)

@app.route('/api/scan_results/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    scan = mongo.db.scans.find_one({"scan_id": scan_id})

    if not scan:
        return jsonify({"error": "Scan results not found"}), 404  # Clear error if scan is missing

    return jsonify({
        "scan_id": scan["scan_id"],
        "target": scan["target"],
        "status": scan["status"],
        "security_headers_results": scan.get("security_headers_results", {}),
        "duckduckgo_results": scan.get("duckduckgo_results", {}),
        "google_safe_browsing_results": scan.get("google_safe_browsing_results", {}),
        "recommendations": scan.get("recommendations", {}),
        "timestamp": scan["timestamp"]
    })

def generate_recommendations(scan_results):
    recommendations = {
        "Security Headers": [],
        "Privacy Trackers": [],
        "Safe Browsing": []
    }

    # Security Headers Recommendations
    if "error" in scan_results["security_headers_results"]:
        recommendations["Security Headers"].append({
            "issue": "Security Headers Check Failed",
            "severity": "High",
            "explanation": "The scan could not retrieve security headers. Ensure the domain is accessible and implements standard security headers.",
            "fix": "Use a security headers tool to manually verify HTTP response headers.",
            "steps": [
                "Check response headers in the browser dev tools.",
                "Ensure CSP, HSTS, X-Frame-Options, and other essential headers are set.",
                "Use securityheaders.com for validation."
            ]
        })

    # Privacy Trackers Recommendations
    if "error" in scan_results["duckduckgo_results"] or scan_results["duckduckgo_results"].get("trackers_found", 0) > 0:
        recommendations["Privacy Trackers"].append({
            "issue": "Trackers Detected",
            "severity": "Medium",
            "explanation": "The website includes third-party tracking scripts that may impact user privacy.",
            "fix": "Reduce the number of tracking scripts or use privacy-respecting alternatives.",
            "steps": [
                "Review scripts using browser extensions like uBlock Origin.",
                "Replace third-party trackers with privacy-focused tools like Matomo.",
                "Implement a strict Content Security Policy (CSP)."
            ]
        })

    # Google Safe Browsing Recommendations
    if scan_results["google_safe_browsing_results"].get("risk", "Low") == "High":
        recommendations["Safe Browsing"].append({
            "issue": "Site Flagged as Unsafe",
            "severity": "Critical",
            "explanation": "Google Safe Browsing detected potential phishing, malware, or harmful content.",
            "fix": "Investigate and remove any harmful content immediately.",
            "steps": [
                "Check Google Search Console for security alerts.",
                "Remove malicious code or injected scripts.",
                "Request a review from Google after resolving issues."
            ]
        })

    return recommendations

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, ssl_context=('cert.pem', 'key.pem'))
  # Enable SSL for local development
    