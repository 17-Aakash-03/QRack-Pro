import gspread
from google.oauth2.service_account import Credentials
import hashlib
import random
import string
from datetime import datetime
import json
import os

SCOPES = [
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/drive'
]

SHEET_ID = '1mcPRkfHR3CmU2XZ3SE1LMtYzJIaanx0U1hywoLy2wE4'

def get_client():
    # Load from file locally, from env variable on Render
    creds_json = os.environ.get('GOOGLE_CREDENTIALS')
    if creds_json:
        info = json.loads(creds_json)
    else:
        with open('credentials.json', 'r') as f:
            info = json.load(f)
    creds = Credentials.from_service_account_info(info, scopes=SCOPES)
    return gspread.authorize(creds)

def get_sheet(name):
    client = get_client()
    sh = client.open_by_key(SHEET_ID)
    try:
        return sh.worksheet(name)
    except gspread.WorksheetNotFound:
        return sh.add_worksheet(title=name, rows=1000, cols=20)

def init_db():
    # Initialize Users sheet
    users_ws = get_sheet('Users')
    if not users_ws.get_all_values():
        users_ws.append_row(['id','username','password','role','can_edit',
                             'can_access_excel','email','reset_token'])
        # Default teamhead
        users_ws.append_row([
            '1', 'teamhead', hash_password('admin123'),
            'head', '1', '1', '', ''
        ])

    # Initialize ScanLogs sheet
    logs_ws = get_sheet('ScanLogs')
    if not logs_ws.get_all_values():
        logs_ws.append_row(['id','qr_id','scanned_by','timestamp','remark','verification_status'])

    # Initialize Settings sheet
    settings_ws = get_sheet('Settings')
    if not settings_ws.get_all_values():
        settings_ws.append_row(['key','value'])
        settings_ws.append_row(['shared','0'])
        settings_ws.append_row(['access_code', gen_code()])

def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

def gen_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

def _get_users_data():
    ws = get_sheet('Users')
    rows = ws.get_all_values()
    if len(rows) < 2:
        return [], ws
    headers = rows[0]
    users = []
    for r in rows[1:]:
        if any(r):
            u = {}
            for i, h in enumerate(headers):
                u[h] = r[i] if i < len(r) else ''
            users.append(u)
    return users, ws

def get_user(username):
    users, _ = _get_users_data()
    for u in users:
        if u.get('username','').lower() == username.lower():
            u['can_edit'] = int(u.get('can_edit',0) or 0)
            u['can_access_excel'] = int(u.get('can_access_excel',0) or 0)
            return u
    return None

def get_user_by_email(email):
    users, _ = _get_users_data()
    for u in users:
        if u.get('email','').lower() == email.lower():
            u['can_edit'] = int(u.get('can_edit',0) or 0)
            u['can_access_excel'] = int(u.get('can_access_excel',0) or 0)
            return u
    return None

def get_user_by_token(token):
    users, _ = _get_users_data()
    for u in users:
        if u.get('reset_token','') == token and token:
            return u
    return None

def get_all_users():
    users, _ = _get_users_data()
    result = []
    for u in users:
        result.append({
            'id': u.get('id',''),
            'username': u.get('username',''),
            'role': u.get('role','member'),
            'can_edit': int(u.get('can_edit',0) or 0),
            'can_access_excel': int(u.get('can_access_excel',0) or 0),
            'email': u.get('email','')
        })
    return result

def _find_user_row(ws, username):
    rows = ws.get_all_values()
    for i, r in enumerate(rows):
        if r and r[1].lower() == username.lower():
            return i + 1  # 1-indexed
    return None

def _find_row_by_col(ws, col_idx, value):
    rows = ws.get_all_values()
    for i, r in enumerate(rows):
        if r and len(r) > col_idx and r[col_idx] == value:
            return i + 1
    return None

def create_user(username, password, role='member', can_edit=0, email=None, can_access_excel=0):
    users, ws = _get_users_data()
    for u in users:
        if u.get('username','').lower() == username.lower():
            return False
    # Generate new ID
    ids = [int(u.get('id',0)) for u in users if str(u.get('id','')).isdigit()]
    new_id = str(max(ids) + 1) if ids else '1'
    ws.append_row([
        new_id, username, hash_password(password),
        role, str(can_edit), str(can_access_excel),
        email or '', ''
    ])
    return True

def _update_user_field(username, field, value):
    ws = get_sheet('Users')
    headers = ws.row_values(1)
    try:
        col = headers.index(field) + 1
    except ValueError:
        return
    row = _find_user_row(ws, username)
    if row:
        ws.update_cell(row, col, value)

def _update_user_field_by_id(uid, field, value):
    ws = get_sheet('Users')
    rows = ws.get_all_values()
    headers = rows[0]
    try:
        col = headers.index(field) + 1
    except ValueError:
        return
    for i, r in enumerate(rows[1:], start=2):
        if r and r[0] == str(uid):
            ws.update_cell(i, col, value)
            return

def update_user_permission(uid, can_edit):
    _update_user_field_by_id(uid, 'can_edit', str(can_edit))

def update_user_excel_access(uid, can_access):
    _update_user_field_by_id(uid, 'can_access_excel', str(can_access))

def update_user_password(uid, new_password):
    _update_user_field_by_id(uid, 'password', hash_password(new_password))

def update_user_email(uid, email):
    _update_user_field_by_id(uid, 'email', email)

def set_reset_token(uid, token):
    _update_user_field_by_id(uid, 'reset_token', token)

def clear_reset_token(uid):
    _update_user_field_by_id(uid, 'reset_token', '')

def delete_user(uid):
    ws = get_sheet('Users')
    rows = ws.get_all_values()
    for i, r in enumerate(rows[1:], start=2):
        if r and r[0] == str(uid):
            ws.delete_rows(i)
            return

def log_scan(qr_id, scanned_by, remark, verification_status):
    ws = get_sheet('ScanLogs')
    rows = ws.get_all_values()
    new_id = str(len(rows))
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ws.append_row([new_id, qr_id, scanned_by, timestamp, remark or '', verification_status or ''])

def get_scan_logs():
    ws = get_sheet('ScanLogs')
    rows = ws.get_all_values()
    if len(rows) < 2:
        return []
    headers = rows[0]
    logs = []
    for r in reversed(rows[1:]):
        if any(r):
            log = {}
            for i, h in enumerate(headers):
                log[h] = r[i] if i < len(r) else ''
            logs.append(log)
    return logs

def get_scan_logs_by_user(username):
    logs = get_scan_logs()
    return [l for l in logs if l.get('scanned_by','') == username]

def get_scan_logs_by_qr(qr_id):
    logs = get_scan_logs()
    return [l for l in logs if l.get('qr_id','') == qr_id]

def get_excel_access():
    ws = get_sheet('Settings')
    rows = ws.get_all_values()
    result = {'shared': '0', 'access_code': ''}
    for r in rows[1:]:
        if r and len(r) >= 2:
            result[r[0]] = r[1]
    return result

def set_excel_shared(shared):
    ws = get_sheet('Settings')
    rows = ws.get_all_values()
    for i, r in enumerate(rows[1:], start=2):
        if r and r[0] == 'shared':
            ws.update_cell(i, 2, '1' if shared else '0')
            return
    ws.append_row(['shared', '1' if shared else '0'])

def regenerate_code():
    code = gen_code()
    ws = get_sheet('Settings')
    rows = ws.get_all_values()
    for i, r in enumerate(rows[1:], start=2):
        if r and r[0] == 'access_code':
            ws.update_cell(i, 2, code)
            return code
    ws.append_row(['access_code', code])
    return code

def verify_access_code(code):
    info = get_excel_access()
    return info.get('access_code','') == code and info.get('shared','0') == '1'