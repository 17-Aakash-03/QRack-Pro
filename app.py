from flask import Flask, jsonify, request, render_template, send_file, session, url_for
import pandas as pd
import os, io, qrcode, secrets
from flask_mail import Mail, Message
from database import (init_db, hash_password, get_user, get_user_by_email,
                       get_user_by_token, create_user, log_scan, get_scan_logs,
                       get_all_users, delete_user, update_user_permission,
                       update_user_password, update_user_email, set_reset_token,
                       clear_reset_token, set_excel_shared, get_excel_access,
                       regenerate_code, verify_access_code)
from functools import wraps

app = Flask(__name__, static_folder='templates', static_url_path='/static')
app.secret_key = "qrack_secret_2024"
EXCEL_FILE = "inventory.xlsx"

# Mail config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'aakashkumarjha44@gmail.com'
app.config['MAIL_PASSWORD'] = 'bjbdkgafrxajiyqs'
app.config['MAIL_DEFAULT_SENDER'] = 'aakashkumarjha241@gmail.com'
mail = Mail(app)

init_db()
if not os.path.exists(EXCEL_FILE):
    import subprocess
    subprocess.run(["python", "generate_qr.py"])

def load_data():
    return pd.read_excel(EXCEL_FILE, dtype=str)

def save_data(df):
    df.to_excel(EXCEL_FILE, index=False)

def login_required(f):
    @wraps(f)
    def d(*a, **k):
        if 'username' not in session:
            return jsonify({"error": "Login required"}), 401
        return f(*a, **k)
    return d

def head_required(f):
    @wraps(f)
    def d(*a, **k):
        if 'username' not in session:
            return jsonify({"error": "Login required"}), 401
        if session.get('role') != 'head':
            return jsonify({"error": "Team head only"}), 403
        return f(*a, **k)
    return d

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/reset-password-page")
def reset_password_page():
    token = request.args.get('token', '')
    return render_template("index.html", reset_token=token)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    expected_role = data.get("expected_role", "")
    user = get_user(data.get("username", ""))
    if user and user['password'] == hash_password(data.get("password", "")):
        if expected_role and user['role'] != expected_role:
            return jsonify({"error": f"This account is not a {expected_role}."}), 401
        session['username'] = user['username']
        session['role'] = user['role']
        session['can_edit'] = user['can_edit']
        session['excel_access'] = user['role'] == 'head'
        return jsonify({"success": True, "username": user['username'],
                        "role": user['role'], "can_edit": user['can_edit'],
                        "excel_access": user['role'] == 'head'})
    return jsonify({"error": "Invalid username or password"}), 401

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/me")
def me():
    if 'username' not in session:
        return jsonify({"logged_in": False})
    user = get_user(session['username'])
    if user:
        session['can_edit'] = user['can_edit']
    return jsonify({"logged_in": True, "username": session['username'],
                    "role": session['role'], "can_edit": session.get('can_edit', 0),
                    "excel_access": session.get('excel_access', False)})

@app.route("/my-permissions")
@login_required
def my_permissions():
    user = get_user(session['username'])
    if user:
        session['can_edit'] = user['can_edit']
        return jsonify({"can_edit": user['can_edit'], "role": user['role']})
    return jsonify({"can_edit": 0, "role": "member"})

@app.route("/register-head", methods=["POST"])
def register_head():
    data = request.json
    u = data.get("username", "").strip()
    p = data.get("password", "").strip()
    e = data.get("email", "").strip()
    if not u or not p or not e:
        return jsonify({"error": "Fill all fields including email"}), 400
    if len(p) < 4:
        return jsonify({"error": "Password too short (min 4)"}), 400
    if '@' not in e:
        return jsonify({"error": "Invalid email address"}), 400
    if create_user(u, p, 'head', 1, e):
        return jsonify({"success": True})
    return jsonify({"error": "Username already exists"}), 400

# FORGOT PASSWORD
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.json
    role = data.get("role", "")
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()

    if role == "head":
        # Head: username + email → reset link
        user = get_user(username)
        if not user or user['role'] != 'head':
            return jsonify({"error": "No Team Head found with this username"}), 404
        if not user['email'] or user['email'].lower() != email.lower():
            return jsonify({"error": "Email does not match our records"}), 400
        token = secrets.token_urlsafe(32)
        set_reset_token(user['id'], token)
        reset_url = request.host_url.rstrip('/') + '/reset-password-page?token=' + token
        try:
            msg = Message("QRack — Reset Your Password",
                          recipients=[user['email']])
            msg.html = f"""
            <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px">
              <h2 style="color:#4f46e5">📦 QRack Password Reset</h2>
              <p>Hello <strong>{user['username']}</strong>,</p>
              <p>Click the button below to reset your password:</p>
              <a href="{reset_url}" style="display:inline-block;background:linear-gradient(135deg,#4f46e5,#7c3aed);color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;margin:16px 0">Reset Password</a>
              <p style="color:#6b7280;font-size:13px">This link expires in 1 hour. If you didn't request this, ignore this email.</p>
              <p style="color:#6b7280;font-size:12px">Link: {reset_url}</p>
            </div>"""
            mail.send(msg)
            return jsonify({"success": True, "message": "Reset link sent to your email!"})
        except Exception as ex:
            return jsonify({"error": "Failed to send email: " + str(ex)}), 500

    elif role == "member":
        # Member: username or email → credentials sent to their email
        user = None
        if username:
            user = get_user(username)
            if user and user['role'] != 'member':
                user = None
        if not user and email:
            user = get_user_by_email(email)
            if user and user['role'] != 'member':
                user = None
        if not user:
            return jsonify({"error": "No member found with this username or email"}), 404
        if not user['email']:
            return jsonify({"error": "No email on file. Contact your Team Head."}), 400

        # Get plain password — we can't since it's hashed
        # Send username and ask head to reset
        try:
            # Find team head
            all_users = get_all_users()
            heads = [u for u in all_users if u['role'] == 'head' and u['email']]

            # Send to member's email
            msg = Message("QRack — Your Login Details",
                          recipients=[user['email']])
            msg.html = f"""
            <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px">
              <h2 style="color:#7c3aed">📦 QRack Login Info</h2>
              <p>Hello <strong>{user['username']}</strong>,</p>
              <p>Your login credentials:</p>
              <div style="background:#f5f3ff;border:2px solid #c4b5fd;border-radius:10px;padding:16px;margin:16px 0">
                <p><strong>Username:</strong> {user['username']}</p>
                <p style="margin-top:8px"><strong>Password:</strong> Contact your Team Head to reset your password.</p>
              </div>
              <p style="color:#6b7280;font-size:13px">Only your Team Head can reset your password. Please contact them directly.</p>
            </div>"""
            mail.send(msg)

            # Also notify head
            for head in heads:
                try:
                    msg2 = Message("QRack — Member Password Reset Request",
                                   recipients=[head['email']])
                    msg2.html = f"""
                    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px">
                      <h2 style="color:#4f46e5">📦 QRack — Password Reset Request</h2>
                      <p>Hello <strong>{head['username']}</strong>,</p>
                      <p>Team member <strong>{user['username']}</strong> has requested their password.</p>
                      <p>Please login to QRack and reset their password from the Team tab.</p>
                      <p style="color:#6b7280;font-size:13px">Login at: {request.host_url}</p>
                    </div>"""
                    mail.send(msg2)
                except: pass

            return jsonify({"success": True, "message": "Your username has been sent to your email. Your Team Head has been notified to reset your password."})
        except Exception as ex:
            return jsonify({"error": "Failed to send email: " + str(ex)}), 500

    return jsonify({"error": "Invalid role"}), 400

# RESET PASSWORD (Head only via token)
@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.json
    token = data.get("token", "").strip()
    new_password = data.get("password", "").strip()
    if not token or not new_password:
        return jsonify({"error": "Invalid request"}), 400
    if len(new_password) < 4:
        return jsonify({"error": "Password too short"}), 400
    user = get_user_by_token(token)
    if not user:
        return jsonify({"error": "Invalid or expired reset link"}), 400
    update_user_password(user['id'], new_password)
    clear_reset_token(user['id'])
    return jsonify({"success": True, "message": "Password reset successfully!"})

@app.route("/verify-code", methods=["POST"])
@login_required
def verify_code():
    code = request.json.get("code", "").strip().upper()
    if verify_access_code(code):
        session['excel_access'] = True
        return jsonify({"success": True})
    return jsonify({"error": "Invalid or expired code"}), 400

@app.route("/users", methods=["GET"])
@head_required
def get_users():
    return jsonify(get_all_users())

@app.route("/users", methods=["POST"])
@head_required
def add_user():
    data = request.json
    u = data.get("username", "").strip()
    p = data.get("password", "").strip()
    e = data.get("email", "").strip()
    if not u or not p:
        return jsonify({"error": "Fill all fields"}), 400
    if len(p) < 4:
        return jsonify({"error": "Password too short"}), 400
    if create_user(u, p, data.get("role", "member"), 1 if data.get("can_edit") else 0, e if e else None):
        # Send welcome email to member
        if e and data.get("role", "member") == "member":
            try:
                msg = Message("QRack — Your Account Details",
                              recipients=[e])
                msg.html = f"""
                <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px">
                  <h2 style="color:#7c3aed">📦 Welcome to QRack!</h2>
                  <p>Hello <strong>{u}</strong>,</p>
                  <p>Your Team Head has created an account for you:</p>
                  <div style="background:#f5f3ff;border:2px solid #c4b5fd;border-radius:10px;padding:16px;margin:16px 0">
                    <p><strong>Username:</strong> {u}</p>
                    <p style="margin-top:8px"><strong>Password:</strong> {p}</p>
                    <p style="margin-top:8px"><strong>Edit Permission:</strong> {'Yes' if data.get('can_edit') else 'No'}</p>
                  </div>
                  <p>Login at: <a href="{request.host_url}">{request.host_url}</a></p>
                  <p style="color:#6b7280;font-size:13px">Select "Team Member" on the login page.</p>
                </div>"""
                mail.send(msg)
            except: pass
        return jsonify({"success": True})
    return jsonify({"error": "Username already exists"}), 400

@app.route("/users/<int:uid>", methods=["DELETE"])
@head_required
def remove_user(uid):
    delete_user(uid)
    return jsonify({"success": True})

@app.route("/users/<int:uid>/permission", methods=["POST"])
@head_required
def update_perm(uid):
    can_edit = 1 if request.json.get("can_edit") else 0
    update_user_permission(uid, can_edit)
    return jsonify({"success": True, "can_edit": can_edit})

@app.route("/users/<int:uid>/password", methods=["POST"])
@head_required
def change_member_password(uid):
    data = request.json
    new_pass = data.get("password", "").strip()
    if not new_pass or len(new_pass) < 4:
        return jsonify({"error": "Password too short (min 4)"}), 400
    update_user_password(uid, new_pass)
    # Get user and send email if they have one
    all_u = get_all_users()
    user = next((u for u in all_u if u['id'] == uid), None)
    if user and user.get('email'):
        try:
            msg = Message("QRack — Your Password Has Been Changed",
                          recipients=[user['email']])
            msg.html = f"""
            <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px">
              <h2 style="color:#7c3aed">📦 QRack Password Updated</h2>
              <p>Hello <strong>{user['username']}</strong>,</p>
              <p>Your Team Head has updated your password:</p>
              <div style="background:#f5f3ff;border:2px solid #c4b5fd;border-radius:10px;padding:16px;margin:16px 0">
                <p><strong>Username:</strong> {user['username']}</p>
                <p style="margin-top:8px"><strong>New Password:</strong> {new_pass}</p>
              </div>
              <p>Login at: <a href="{request.host_url}">{request.host_url}</a></p>
            </div>"""
            mail.send(msg)
        except: pass
    return jsonify({"success": True})

@app.route("/users/<int:uid>/email", methods=["POST"])
@head_required
def change_member_email(uid):
    email = request.json.get("email", "").strip()
    if not email or '@' not in email:
        return jsonify({"error": "Invalid email"}), 400
    update_user_email(uid, email)
    return jsonify({"success": True})

@app.route("/excel/share", methods=["POST"])
@head_required
def share_excel():
    set_excel_shared(request.json.get("shared", False))
    return jsonify({"success": True})

@app.route("/excel/regenerate-code", methods=["POST"])
@head_required
def regen():
    return jsonify({"success": True, "code": regenerate_code()})

@app.route("/excel/access-info")
@head_required
def access_info():
    return jsonify(get_excel_access())

@app.route("/excel/status")
@login_required
def excel_status():
    try:
        info = get_excel_access()
        if not os.path.exists(EXCEL_FILE):
            return jsonify({"available": False, "shared": False, "has_access": False})
        df = load_data()
        role = session.get('role')
        has_access = role == 'head' or session.get('excel_access', False)
        user = get_user(session['username'])
        can_edit = user['can_edit'] if user else 0
        session['can_edit'] = can_edit
        return jsonify({"available": True, "shared": info.get('shared', 0) == 1,
                        "total_items": len(df), "has_access": has_access, "can_edit": can_edit})
    except:
        return jsonify({"available": False, "shared": False, "has_access": False, "can_edit": 0})

@app.route("/item/<qr_id>", methods=["GET"])
@login_required
def get_item(qr_id):
    try:
        if not session.get('excel_access') and session.get('role') != 'head':
            return jsonify({"error": "Enter access code first"}), 403
        df = load_data()
        row = df[df["QR Code ID"] == qr_id]
        if row.empty:
            return jsonify({"error": "Item not found"}), 404
        return jsonify(row.iloc[0].to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/item/<qr_id>", methods=["POST"])
@login_required
def update_item(qr_id):
    try:
        if not session.get('excel_access') and session.get('role') != 'head':
            return jsonify({"error": "Enter access code first"}), 403
        data = request.json
        remark = data.pop("remark", "")
        role = session.get('role')
        user = get_user(session['username'])
        can_edit = user['can_edit'] if user else 0
        if role != 'head' and not can_edit:
            return jsonify({"error": "No edit permission"}), 403
        df = load_data()
        idx = df[df["QR Code ID"] == qr_id].index
        if idx.empty:
            return jsonify({"error": "Item not found"}), 404
        if role != 'head':
            data.pop('Verification Status', None)
        for k, v in data.items():
            if k in df.columns:
                df.at[idx[0], k] = v
        df.at[idx[0], 'Last Scanned'] = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
        df.at[idx[0], 'Scanned By'] = session['username']
        save_data(df)
        log_scan(qr_id, session['username'], remark, df.at[idx[0], 'Verification Status'])
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/scan-log/<qr_id>", methods=["POST"])
@login_required
def log_scan_only(qr_id):
    try:
        if not session.get('excel_access') and session.get('role') != 'head':
            return jsonify({"error": "Enter access code first"}), 403
        data = request.json
        df = load_data()
        row = df[df["QR Code ID"] == qr_id]
        if row.empty:
            return jsonify({"error": "Item not found"}), 404
        idx = row.index[0]
        df.at[idx, 'Last Scanned'] = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
        df.at[idx, 'Scanned By'] = session['username']
        save_data(df)
        log_scan(qr_id, session['username'], data.get("remark", ""),
                 row.iloc[0].get("Verification Status", ""))
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/items")
@login_required
def get_all_items():
    try:
        if not os.path.exists(EXCEL_FILE):
            return jsonify([])
        return jsonify(load_data().to_dict(orient='records'))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/upload-excel", methods=["POST"])
@head_required
def upload_excel():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file"}), 400
        f = request.files['file']
        if not f.filename.endswith('.xlsx'):
            return jsonify({"error": "Invalid file"}), 400
        f.save(EXCEL_FILE)
        df = load_data()
        new_qr = 0
        os.makedirs("qrcodes", exist_ok=True)
        for _, row in df.iterrows():
            qid = str(row.get("QR Code ID", "")).strip()
            if qid and qid != 'nan' and not os.path.exists(f"qrcodes/{qid}.png"):
                qrcode.make(qid).save(f"qrcodes/{qid}.png")
                new_qr += 1
        return jsonify({"success": True, "total_items": len(df), "new_qr_generated": new_qr})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/qrcode/<qr_id>")
def serve_qr(qr_id):
    path = f"qrcodes/{qr_id}.png"
    if not os.path.exists(path):
        return "Not found", 404
    return send_file(path, mimetype="image/png")

def get_all_logs():
    logs = get_scan_logs()
    log_qr_ids = {l['qr_id'] for l in logs}
    extra_logs = []
    if os.path.exists(EXCEL_FILE):
        try:
            df = load_data()
            for _, row in df.iterrows():
                scanned_by = str(row.get('Scanned By', '')).strip()
                qr_id = str(row.get('QR Code ID', '')).strip()
                last_scanned = str(row.get('Last Scanned', '')).strip()
                status = str(row.get('Verification Status', '')).strip()
                if (scanned_by and scanned_by != 'nan' and
                    qr_id and qr_id != 'nan' and qr_id not in log_qr_ids):
                    extra_logs.append({'id': None, 'qr_id': qr_id, 'scanned_by': scanned_by,
                                       'timestamp': last_scanned if last_scanned != 'nan' else '',
                                       'remark': '', 'verification_status': status if status != 'nan' else ''})
        except: pass
    return logs + extra_logs

@app.route("/report")
@head_required
def get_report():
    try:
        all_logs = get_all_logs()
        df = load_data()
        total = len(df)
        return jsonify({"total": total, "scanned": len(all_logs),
            "verified": sum(1 for l in all_logs if l['verification_status'] == 'Verified'),
            "pending": sum(1 for l in all_logs if l['verification_status'] == 'Pending'),
            "rejected": sum(1 for l in all_logs if l['verification_status'] == 'Rejected'),
            "not_scanned": total - len(all_logs), "logs": all_logs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/report/download")
@head_required
def download_report():
    try:
        all_logs = get_all_logs()
        df_inv = load_data() if os.path.exists(EXCEL_FILE) else pd.DataFrame()
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            if not df_inv.empty and all_logs:
                df_l = pd.DataFrame(all_logs)[['qr_id','scanned_by','timestamp','remark','verification_status']]
                df_l.columns = ['QR Code ID','Scanned By','Scan Time','Remark','Scan Status']
                pd.merge(df_inv, df_l, on='QR Code ID', how='left').to_excel(writer, sheet_name='Scan Report', index=False)
            elif not df_inv.empty:
                df_inv.to_excel(writer, sheet_name='Scan Report', index=False)
            total = len(df_inv)
            pd.DataFrame({'Status': ['Total','Scanned','Verified','Pending','Rejected','Not Scanned'],
                'Count': [total, len(all_logs),
                    sum(1 for l in all_logs if l['verification_status']=='Verified'),
                    sum(1 for l in all_logs if l['verification_status']=='Pending'),
                    sum(1 for l in all_logs if l['verification_status']=='Rejected'),
                    total - len(all_logs)]
            }).to_excel(writer, sheet_name='Summary', index=False)
        output.seek(0)
        return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                         as_attachment=True, download_name='QRack_Report.xlsx')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/static/manifest.json')
def manifest():
    return send_file('templates/manifest.json', mimetype='application/manifest+json')

@app.route('/static/sw.js')
def sw():
    return send_file('templates/sw.js', mimetype='application/javascript')

if __name__ == "__main__":
    app.run(debug=False)
