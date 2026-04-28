import secrets
import base64
import json
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet # NEW: Enterprise AES Encryption

app = Flask(__name__)
CORS(app) 

# ==========================================
# 1. GLOBAL SYSTEM STATE & WEBHOOK ENGINE
# ==========================================
system_state = {
    "status": "Active",
    "last_activity": datetime.utcnow(),
    "ttl_days_limit": 14,
    "linked_signals": {"github": None, "etherscan": None},
    "webhook_url": "https://webhook.site/YOUR-UNIQUE-URL-HERE",
    "alerts_sent": {"Escalation": False, "Recovery": False, "Lockdown": False, "Biometric": False},
    "vault_db": {} # NEW: Stores the AES-encrypted payload and files
}

def trigger_webhook_alert(alert_type, message):
    url = system_state["webhook_url"]
    if not url: return
    if system_state["alerts_sent"].get(alert_type): return
    try:
        payload = {"alert_type": alert_type, "message": message, "timestamp": datetime.utcnow().isoformat()}
        requests.post(url, json=payload, timeout=5)
        system_state["alerts_sent"][alert_type] = True
        print(f"[WEBHOOK FIRED] {alert_type}: {message}")
    except Exception as e:
        print(f"[WEBHOOK FAILED] {e}")

# ==========================================
# 2. SHAMIR'S SECRET SHARING MATH ENGINE
# ==========================================
PRIME = 2**127 - 1 

def _eval_at(poly, x, prime):
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum

def _extended_gcd(a, b):
    x, last_x, y, last_y = 0, 1, 1, 0
    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y

def _divmod(num, den, p):
    inv, _ = _extended_gcd(den, p)
    return num * inv

def _lagrange_interpolate(x, x_s, y_s, p):
    k = len(x_s)
    nums, dens = [], []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(1)
        dens.append(1)
        for o in others:
            nums[i] = nums[i] * (x - o)
            dens[i] = dens[i] * (cur - o)
    den = 1
    for d in dens: den = (den * d) % p
    num = 0
    for i in range(k):
        num = (num + _divmod(nums[i] * den * y_s[i] % p, dens[i], p)) % p
    return (_divmod(num, den, p) + p) % p

# ==========================================
# 3. AUTHENTICATION & BIOMETRICS ENGINE
# ==========================================
users_db = {} 

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    avg_speed = data.get('avg_speed', 0)

    if not email or not password: return jsonify({"status": "error", "message": "Email and password required"}), 400
    if email in users_db: return jsonify({"status": "error", "message": "User already exists"}), 400

    users_db[email] = {
        "hash": generate_password_hash(password),
        "baseline_speed": avg_speed
    }
    return jsonify({"status": "success", "message": "Vault profile created successfully!"}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    current_speed = data.get('avg_speed', 0)

    if email not in users_db: return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    user_record = users_db[email]
    if not check_password_hash(user_record["hash"], password):
        trigger_webhook_alert("Escalation", f"Failed login attempt for {email} (Wrong Password)")
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    baseline = user_record["baseline_speed"]
    if baseline > 0 and current_speed > 0:
        deviation = abs(baseline - current_speed) / baseline
        if deviation > 0.40:
            system_state["status"] = "Lockdown"
            system_state["alerts_sent"]["Biometric"] = False
            trigger_webhook_alert("Biometric", f"INTRUSION ATTEMPT: Biometric keystroke anomaly detected for {email}. Deviated by {deviation*100:.1f}%.")
            return jsonify({"status": "error", "message": "Biometric keystroke anomaly detected. System Locked."}), 401

    return jsonify({"status": "success", "message": "Authentication successful"}), 200

# ==========================================
# 4. USER PROFILE ENGINE
# ==========================================
profiles_db = {} 

@app.route('/api/user/profile', methods=['GET', 'POST'])
def manage_profile():
    if request.method == 'POST':
        data = request.json
        email = data.get('email')
        if not email: return jsonify({"status": "error", "message": "Identity marker (email) required"}), 400
            
        profiles_db[email] = {
            "full_name": data.get("full_name", ""),
            "phone": data.get("phone", ""),
            "fiduciary_contact": data.get("fiduciary_contact", ""),
            "identity_secured": True
        }
        return jsonify({"status": "success", "message": "Vault Identity Secured!"}), 200

    email = request.args.get('email')
    profile = profiles_db.get(email, {"full_name": "", "phone": "", "fiduciary_contact": "", "identity_secured": False})
    return jsonify({"status": "success", "profile": profile}), 200

# ==========================================
# 5. HYBRID VAULT ENDPOINTS (AES + SSS)
# ==========================================
@app.route('/api/vault/seal', methods=['POST'])
def seal_vault():
    data = request.json
    text_payload = data.get('payload', '')
    file_data = data.get('file_data', None) # Base64 encoded file
    file_name = data.get('file_name', None)
    file_type = data.get('file_type', None)
    n_shares = int(data.get('n_shares', 5))
    k_threshold = int(data.get('k_threshold', 3))

    # 1. Generate AES Master Key (14 hex chars = 56 bits, easily fits in PRIME)
    master_secret = secrets.token_hex(7) 
    secret_int = int(master_secret, 16)

    # 2. Derive Fernet AES Key from the Master Secret
    padded_secret = master_secret.ljust(32, '0').encode('utf-8')
    aes_key = base64.urlsafe_b64encode(padded_secret)
    cipher = Fernet(aes_key)

    # 3. Encrypt the Text and File Data with AES-256
    encrypted_text = cipher.encrypt(text_payload.encode('utf-8')).decode('utf-8') if text_payload else ""
    encrypted_file = cipher.encrypt(file_data.encode('utf-8')).decode('utf-8') if file_data else None

    # 4. Store encrypted payload in the Vault DB
    system_state["vault_db"] = {
        "text": encrypted_text,
        "file": encrypted_file,
        "file_name": file_name,
        "file_type": file_type
    }

    # 5. Shatter the Master Secret using Shamir's Secret Sharing
    poly = [secret_int] + [secrets.randbelow(PRIME) for _ in range(k_threshold - 1)]
    points = [(i, _eval_at(poly, i, PRIME)) for i in range(1, n_shares + 1)]
    
    formatted_shares = []
    for point in points:
        share_str = json.dumps({"x": point[0], "y": point[1]})
        encoded = base64.b64encode(share_str.encode('utf-8')).decode('utf-8')
        formatted_shares.append(encoded)

    return jsonify({"status": "success", "shares": formatted_shares}), 200

@app.route('/api/vault/recover', methods=['POST'])
def recover_vault():
    if system_state["status"] == "Active" or system_state["status"] == "Escalation":
        return jsonify({"status": "error", "message": "Vault is currently SEALED. Owner is active."}), 403

    data = request.json
    shares_b64 = data.get('shares', [])
    try:
        x_s, y_s = [], []
        for b64 in shares_b64:
            if not b64: continue
            decoded = json.loads(base64.b64decode(b64).decode('utf-8'))
            x_s.append(decoded['x'])
            y_s.append(decoded['y'])
            
        # 1. Reconstruct the Secret Integer
        secret_int = _lagrange_interpolate(0, x_s, y_s, PRIME)
        
        # 2. Convert back to the Master Secret hex string
        master_secret = hex(secret_int)[2:].zfill(14)
        
        # 3. Derive the AES Key
        padded_secret = master_secret.ljust(32, '0').encode('utf-8')
        aes_key = base64.urlsafe_b64encode(padded_secret)
        cipher = Fernet(aes_key)
        
        # 4. Decrypt the Vault contents
        vault = system_state.get("vault_db", {})
        decrypted_text = cipher.decrypt(vault["text"].encode('utf-8')).decode('utf-8') if vault.get("text") else ""
        decrypted_file = cipher.decrypt(vault["file"].encode('utf-8')).decode('utf-8') if vault.get("file") else None

        return jsonify({
            "status": "success", 
            "recovered_text": decrypted_text,
            "recovered_file": decrypted_file,
            "file_name": vault.get("file_name"),
            "file_type": vault.get("file_type")
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": "Cryptographic mismatch. Invalid threshold or corrupt data."}), 400

# ==========================================
# 6. OMNI-SIGNAL ENDPOINTS
# ==========================================
ETHERSCAN_API_KEY = "" 

@app.route('/api/signals/link', methods=['POST'])
def link_signal():
    data = request.json
    platform = data.get('platform')
    identifier = data.get('identifier')
    
    if platform in system_state["linked_signals"]:
        system_state["linked_signals"][platform] = identifier
        return jsonify({"status": "success", "message": f"{platform.capitalize()} linked successfully!"}), 200
    return jsonify({"status": "error", "message": "Invalid platform"}), 400

@app.route('/api/signals/sync', methods=['GET'])
def sync_signals():
    results = []
    activity_found = False
    
    if system_state["linked_signals"]['github']:
        username = system_state["linked_signals"]['github']
        try:
            gh_res = requests.get(f"https://api.github.com/users/{username}/events/public")
            if gh_res.status_code == 200 and len(gh_res.json()) > 0:
                latest_event = gh_res.json()[0]
                event_date = datetime.strptime(latest_event['created_at'], "%Y-%m-%dT%H:%M:%SZ")
                days_ago = (datetime.utcnow() - event_date).days
                results.append({"platform": "GitHub", "status": "Active", "last_seen": f"{days_ago} days ago", "event_type": latest_event['type']})
                if days_ago < 2: activity_found = True
            else:
                results.append({"platform": "GitHub", "status": "Inactive", "last_seen": "No recent activity"})
        except Exception as e:
            results.append({"platform": "GitHub", "status": "Error", "message": str(e)})

    if system_state["linked_signals"]['etherscan']:
        address = system_state["linked_signals"]['etherscan']
        try:
            url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page=1&offset=1&sort=desc"
            if ETHERSCAN_API_KEY: url += f"&apikey={ETHERSCAN_API_KEY}"
            eth_res = requests.get(url)
            eth_data = eth_res.json()
            if eth_data['status'] == '1' and len(eth_data['result']) > 0:
                latest_tx = eth_data['result'][0]
                tx_date = datetime.utcfromtimestamp(int(latest_tx['timeStamp']))
                days_ago = (datetime.utcnow() - tx_date).days
                results.append({"platform": "Etherscan", "status": "Active", "last_seen": f"{days_ago} days ago", "event_type": "Transaction"})
                if days_ago < 2: activity_found = True
            else:
                results.append({"platform": "Etherscan", "status": "Inactive", "last_seen": "No recent transactions"})
        except Exception as e:
            results.append({"platform": "Etherscan", "status": "Error", "message": str(e)})

    if activity_found and system_state["status"] != "Lockdown":
        system_state["last_activity"] = datetime.utcnow()
        system_state["status"] = "Active"
        system_state["alerts_sent"] = {k: False for k in system_state["alerts_sent"]}

    if not results:
        return jsonify({"status": "idle", "results": []}), 200

    return jsonify({"status": "success", "results": results}), 200

# ==========================================
# 7. DASHBOARD ENDPOINTS
# ==========================================
@app.route('/api/system/state', methods=['GET'])
def get_state():
    now = datetime.utcnow()
    expiration_date = system_state["last_activity"] + timedelta(days=system_state["ttl_days_limit"])
    time_left = expiration_date - now

    if system_state["status"] != "Lockdown":
        if time_left.total_seconds() <= 0:
            system_state["status"] = "Recovery"
            trigger_webhook_alert("Recovery", "TTL EXPIRED: Digital Estate is now unlocked for Fiduciaries.")
            time_left = timedelta(seconds=0)
        elif time_left.days < 3:
            system_state["status"] = "Escalation"
            trigger_webhook_alert("Escalation", "WARNING: 3 Days until TTL expiration. Please verify identity.")
        else:
            system_state["status"] = "Active"
            system_state["alerts_sent"] = {k: False for k in system_state["alerts_sent"]}

    days = time_left.days
    hours, remainder = divmod(time_left.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    return jsonify({
        "status": system_state["status"],
        "last_activity_date": system_state["last_activity"].strftime("%Y-%m-%d %H:%M:%S UTC"),
        "days_since": (now - system_state["last_activity"]).days,
        "countdown": {
            "days": max(0, days),
            "hours": hours,
            "minutes": minutes,
            "seconds": seconds
        }
    }), 200

@app.route('/api/signals/simulate_activity', methods=['POST'])
def simulate_activity():
    system_state["last_activity"] = datetime.utcnow()
    system_state["status"] = "Active"
    system_state["alerts_sent"] = {k: False for k in system_state["alerts_sent"]}
    return jsonify({"message": "Heartbeat detected. TTL Reset."}), 200

@app.route('/api/security/honeypot_trigger', methods=['POST'])
def trigger_lockdown():
    system_state["status"] = "Lockdown"
    system_state["alerts_sent"]["Lockdown"] = False
    trigger_webhook_alert("Lockdown", "CRITICAL INTRUSION: Honeypot triggered. System frozen indefinitely.")
    return jsonify({"message": "SYSTEM LOCKDOWN ENGAGED"}), 200

@app.route('/api/system/webhook', methods=['POST'])
def config_webhook():
    system_state["webhook_url"] = request.json.get('url')
    return jsonify({"message": "Webhook updated"}), 200

if __name__ == '__main__':
    app.run(port=5000, debug=True)