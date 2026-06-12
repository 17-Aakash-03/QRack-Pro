from flask import Flask, jsonify, request, render_template, send_file, session
import pandas as pd
import os, io, qrcode
from database import (init_db, hash_password, get_user, create_user, log_scan,
                       get_scan_logs, get_all_users, delete_user, update_user_permission,
                       set_excel_shared, get_excel_access, regenerate_code, verify_access_code)
from functools import wraps

app = Flask(__name__, static_folder='templates', static_url_path='/static')
app.secret_key = "qrack_secret_2024"
EXCEL_FILE = "inventory.xlsx"

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

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    expected_role = data.get("expected_role", "")
    user = get_user(data.get("username", ""))
    if user and user['password'] == hash_password(data.get("password", "")):
        if expected_role and user['role'] != expected_role:
            return jsonify({"error": f"This account is not a {expected_role}"}), 401
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
    return jsonify({"logged_in": True, "username": session['username'],
                    "role": session['role'], "can_edit": session.get('can_edit', 0),
                    "excel_access": session.get('excel_access', False)})

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    u = data.get("username", "").strip()
    p = data.get("password", "").strip()
    if not u or not p:
        return jsonify({"error": "Fill all fields"}), 400
    if len(p) < 4:
        return jsonify({"error": "Password too short"}), 400
    if create_user(u, p, 'member', 0):
        return jsonify({"success": True})
    return jsonify({"error": "Username already exists"}), 400

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
    if not u or not p:
        return jsonify({"error": "Fill all fields"}), 400
    if create_user(u, p, data.get("role", "member"), 1 if data.get("can_edit") else 0):
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
    update_user_permission(uid, 1 if request.json.get("can_edit") else 0)
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
        return jsonify({"available": True, "shared": info.get('shared', 0) == 1,
                        "total_items": len(df), "has_access": has_access})
    except:
        return jsonify({"available": False, "shared": False, "has_access": False})

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
        can_edit = session.get('can_edit', 0)
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
        log_scan(qr_id, session['username'], data.get("remark", ""), row.iloc[0].get("Verification Status", ""))
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

@app.route("/report")
@head_required
def get_report():
    try:
        logs = get_scan_logs()
        df = load_data()
        total = len(df)
        return jsonify({"total": total, "scanned": len(logs),
            "verified": sum(1 for l in logs if l['verification_status'] == 'Verified'),
            "pending": sum(1 for l in logs if l['verification_status'] == 'Pending'),
            "rejected": sum(1 for l in logs if l['verification_status'] == 'Rejected'),
            "not_scanned": total - len(logs), "logs": logs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/report/download")
@head_required
def download_report():
    try:
        logs = get_scan_logs()
        df_inv = load_data() if os.path.exists(EXCEL_FILE) else pd.DataFrame()
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            if not df_inv.empty and logs:
                df_l = pd.DataFrame(logs)[['qr_id','scanned_by','timestamp','remark','verification_status']]
                df_l.columns = ['QR Code ID','Scanned By','Scan Time','Remark','Scan Status']
                pd.merge(df_inv, df_l, on='QR Code ID', how='left').to_excel(writer, sheet_name='Scan Report', index=False)
            pd.DataFrame({'Status': ['Total','Scanned','Verified','Pending','Rejected','Not Scanned'],
                'Count': [len(df_inv), len(logs),
                    sum(1 for l in logs if l['verification_status']=='Verified'),
                    sum(1 for l in logs if l['verification_status']=='Pending'),
                    sum(1 for l in logs if l['verification_status']=='Rejected'),
                    len(df_inv) - len(logs)]
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