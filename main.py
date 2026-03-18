from flask import Flask, render_template, request, redirect, session, url_for, send_file, jsonify
import json, os, subprocess, uuid, base64, re
from datetime import datetime, timedelta

from config import SECRET_KEY, USERS_DB, NODES_LIST, CONFIG_FILE, ADMIN_PASS, load_config, save_config
from utils import get_nodes, check_live_status, get_safe_delete_cmd

app = Flask(__name__)
app.secret_key = SECRET_KEY

@app.before_request
def check_auth():
    if request.endpoint not in ['login', 'static', 'api_stats'] and not session.get('logged_in'):
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ""
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASS:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else: 
            error = "❌ Password မှားယွင်းနေပါသည်။"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout(): 
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    nodes = get_nodes()
    db = {}
    if os.path.exists(USERS_DB):
        try:
            with open(USERS_DB, 'r') as f: db = json.load(f)
        except: pass
        
    config = load_config()
    active_users = check_live_status(db)
    
    node_stats = []
    all_users = []
    for n_name, n_ip in nodes.items():
        total_count = 0; live_count = 0
        for uname, info in db.items():
            if info.get('node') == n_name:
                total_count += 1
                if uname in active_users and not info.get('is_blocked'): live_count += 1
                all_users.append({'username': uname, 'node': n_name, 'key': info.get('key', 'No Key')})
        node_stats.append({"name": n_name, "ip": n_ip, "total": total_count, "live": live_count, "disabled": n_name in config['disabled_nodes']})
        
    return render_template('dashboard.html', nodes=node_stats, all_users=all_users, config=config)

@app.route('/node/<node_name>')
def node_view(node_name):
    nodes = get_nodes()
    node_ip = nodes.get(node_name, "")
    db = {}
    if os.path.exists(USERS_DB):
        try:
            with open(USERS_DB, 'r') as f: db = json.load(f)
        except: pass
    config = load_config()
    active_users = check_live_status(db)
    users = []
    for uname, info in db.items():
        if info.get('node') == node_name:
            try: used_b = float(info.get('used_bytes') or 0)
            except: used_b = 0.0
            try: tot_gb = float(info.get('total_gb') or 0)
            except: tot_gb = 0.0
            info['used_bytes'] = used_b; info['total_gb'] = tot_gb
            info['used_gb_str'] = f"{(used_b / (1024**3)):.2f}"
            info['username'] = uname
            info['actual_key'] = info.get('key') or info.get('key_val') or "No Key Found"
            info['is_active'] = uname in active_users and not info.get('is_blocked')
            info['is_blocked'] = info.get('is_blocked', False)
            users.append(info)
    return render_template('node.html', node_name=node_name, node_ip=node_ip, users=users, config=config)

# --- API: SSH Connection စစ်ဆေးရန် ---
@app.route('/api/check_ssh/<node_name>')
def check_ssh(node_name):
    nodes = get_nodes()
    node_ip = nodes.get(node_name)
    if not node_ip: return jsonify({"status": "error", "msg": "Node Not Found"})
    try:
        cmd = f"ssh -o ConnectTimeout=3 -o PasswordAuthentication=no -o StrictHostKeyChecking=no root@{node_ip} 'echo ssh_ok'"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if "ssh_ok" in res.stdout:
            return jsonify({"status": "success"})
        return jsonify({"status": "error"})
    except:
        return jsonify({"status": "error"})

# --- API: Xray Active ဖြစ်မဖြစ် စစ်ဆေးရန် ---
@app.route('/api/check_xray/<node_name>')
def check_xray(node_name):
    nodes = get_nodes()
    node_ip = nodes.get(node_name)
    if not node_ip: return jsonify({"status": "inactive"})
    try:
        cmd = f"ssh -o ConnectTimeout=3 -o PasswordAuthentication=no -o StrictHostKeyChecking=no root@{node_ip} 'systemctl is-active xray'"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if "active" in res.stdout.strip().lower():
            return jsonify({"status": "active"})
        return jsonify({"status": "inactive"})
    except:
        return jsonify({"status": "inactive"})

# --- Route: Node အသစ်ထည့်ရန် ---
@app.route('/add_node', methods=['POST'])
def add_node():
    n_name = request.form.get('node_name')
    n_ip = request.form.get('node_ip')
    if n_name and n_ip:
        with open(NODES_LIST, 'a') as f: 
            f.write(f"\n{n_name} {n_ip}")
    return redirect(url_for('node_view', node_name=n_name) + "?newly_added=yes")

# --- Route: Node ဖျက်ရန် ---
# --- Route: Node ဖျက်ရန် ---
@app.route('/delete_node/<node_name>', methods=['POST'])
def delete_node(node_name):
    # (၁) nodes_list.txt ထဲကနေ ရှာဖျက်မယ်
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f: 
            lines = f.readlines()
        with open(NODES_LIST, 'w') as f:
            for line in lines:
                if line.strip():
                    parts = line.split()
                    # စာကြောင်းရဲ့ ပထမဆုံးနာမည်က ဖျက်မယ့် Node နဲ့ မတူမှသာ ပြန်သိမ်းမယ်
                    if len(parts) >= 1 and parts[0] != node_name:
                        f.write(line)
                        
    # (၂) Disabled လုပ်ထားတဲ့ စာရင်းထဲမှာ ပါနေခဲ့ရင်ပါ တစ်ခါတည်း ရှင်းထုတ်မယ်
    config = load_config()
    if node_name in config.get('disabled_nodes', []):
        config['disabled_nodes'].remove(node_name)
        save_config(config)
        
    return redirect(url_for('dashboard'))

# --- Route: Node ဆီသို့ Script အလိုအလျောက် သွင်းရန် ---
@app.route('/install_node/<node_name>', methods=['POST'])
def install_node_action(node_name):
    nodes = get_nodes()
    node_ip = nodes.get(node_name)
    if node_ip:
        script_path = "/root/PanelMaster/install_node.sh"
        if os.path.exists(script_path):
            cmd = f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{node_ip} 'bash -s' < {script_path}"
            subprocess.run(cmd, shell=True)
    return redirect(f'/node/{node_name}')

@app.route('/api/stats/<node_name>')
def api_stats(node_name):
    if not session.get('logged_in'): return jsonify({"status": "error"})
    nodes = get_nodes(); node_ip = nodes.get(node_name)
    if not node_ip: return jsonify({"status": "error"})
    try:
        cmd = f"ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no root@{node_ip} \"/usr/local/bin/xray api statsquery --server=127.0.0.1:10085\""
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if res.stdout.strip():
            stats = json.loads(res.stdout).get("stat", [])
            user_bytes = {}
            for s in stats:
                parts = s.get("name", "").split(">>>")
                if len(parts) >= 4:
                    uname = parts[1]
                    val = s.get("value", 0)
                    user_bytes[uname] = user_bytes.get(uname, 0) + val
            return jsonify({"status": "ok", "data": user_bytes})
    except: pass
    return jsonify({"status": "error"})

@app.route('/toggle_node/<node_name>', methods=['POST'])
def toggle_node(node_name):
    config = load_config()
    nodes = get_nodes()
    node_ip = nodes.get(node_name)
    if node_name in config['disabled_nodes']:
        config['disabled_nodes'].remove(node_name)
        if node_ip: os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} 'systemctl start xray'")
    else:
        config['disabled_nodes'].append(node_name)
        if node_ip: os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} 'systemctl stop xray'")
    save_config(config)
    return redirect(f'/node/{node_name}')

@app.route('/add_user_manual', methods=['POST'])
def add_user_manual():
    creation_mode = request.form.get('creation_mode', 'single')
    usernames = []
    if creation_mode == 'single':
        u = request.form.get('single_username', '').strip()
        if u: usernames.append(u)
    elif creation_mode == 'list':
        raw = request.form.get('list_usernames', '')
        usernames = [u.strip() for u in re.split(r'[,\n]+', raw) if u.strip()]
    elif creation_mode == 'pattern':
        base = request.form.get('base_name', '').strip()
        start = int(request.form.get('start_num', 1))
        qty = int(request.form.get('qty', 1))
        for i in range(qty): usernames.append(f"{base}{start+i}")

    n_name = request.form.get('node_name')
    gb = float(request.form.get('total_gb', 0)); exp = request.form.get('expire_date')
    proto = request.form.get('protocol', 'v2')
    nodes = get_nodes(); n_ip = nodes.get(n_name)
    if not n_ip or not usernames: return redirect(f'/node/{n_name}')
    
    db = {}
    if os.path.exists(USERS_DB):
        with open(USERS_DB, 'r') as f: db = json.load(f)
        
    max_port = 10000
    for u, info in db.items():
        if info.get('protocol') == 'out':
            try:
                p = int(info.get('port', 10000))
                if p > max_port: max_port = p
            except: pass
    
    commands = []; current_port = max_port
    for uname in usernames:
        if uname in db: continue
        uid = str(uuid.uuid4())
        if proto == 'v2':
            port = "443"
            key_str = f"vless://{uid}@{n_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{uname}"
            commands.append(f"/usr/local/bin/v2ray-node-add-vless {uname} {uid}")
        else:
            current_port += 1; port = str(current_port)
            ss_conf = base64.b64encode(f"chacha20-ietf-poly1305:{uid}".encode()).decode()
            key_str = f"ss://{ss_conf}@{n_ip}:{port}#{uname}"
            commands.append(f"/usr/local/bin/v2ray-node-add-out {uname} {uid} {port}")
            commands.append(f"ufw allow {port}/tcp && ufw allow {port}/udp")
            
        db[uname] = {"node": n_name, "protocol": proto, "uuid": uid, "port": port, "total_gb": gb, "expire_date": exp, "used_bytes": 0, "last_raw_bytes": 0, "is_blocked": False, "key": key_str}
    
    if commands:
        commands.append("systemctl restart xray")
        os.system(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{n_ip} \"{' ; '.join(commands)}\"")
        with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(f'/node/{n_name}')

@app.route('/toggle_user/<username>', methods=['POST'])
def toggle_user(username):
    if os.path.exists(USERS_DB):
        with open(USERS_DB, 'r') as f: db = json.load(f)
        if username in db:
            user = db[username]
            user['is_blocked'] = not user.get('is_blocked', False)
            nodes = get_nodes(); node_ip = nodes.get(user.get('node'))
            if node_ip:
                if user['is_blocked']:
                    safe_cmd = get_safe_delete_cmd(username, user.get('protocol', 'v2'), user.get('port', '443'))
                    os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"{safe_cmd}\"")
                else:
                    uid = user['uuid']
                    if user['protocol'] == 'v2': os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} '/usr/local/bin/v2ray-node-add-vless {username} {uid}'")
                    else: os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} '/usr/local/bin/v2ray-node-add-out {username} {uid} {user['port']}'")
                
                os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} 'systemctl restart xray'")
            with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(request.referrer)

@app.route('/bulk_delete', methods=['POST'])
def bulk_delete():
    node_name = request.form.get('node_name')
    usernames = request.form.getlist('usernames')
    if os.path.exists(USERS_DB):
        with open(USERS_DB, 'r') as f: db = json.load(f)
        nodes = get_nodes(); node_ip = nodes.get(node_name)
        commands = []
        modified = False
        for uname in usernames:
            if uname in db:
                user = db[uname]
                safe_cmd = get_safe_delete_cmd(uname, user.get('protocol', 'v2'), user.get('port', '443'))
                commands.append(safe_cmd)
                del db[uname]
                modified = True
        if modified:
            if node_ip and commands:
                commands.append("systemctl restart xray")
                os.system(f"ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no root@{node_ip} \"{' ; '.join(commands)}\"")
            with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(f'/node/{node_name}')

@app.route('/edit_user/<username>', methods=['POST'])
def edit_user(username):
    new_gb = float(request.form.get('total_gb', 0)); new_date = request.form.get('expire_date', '')
    node_name = request.form.get('node_name', '')
    if os.path.exists(USERS_DB):
        with open(USERS_DB, 'r') as f: db = json.load(f)
        user = db.get(username)
        if user:
            user['total_gb'] = new_gb; user['expire_date'] = new_date
            with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(url_for('node_view', node_name=node_name))

@app.route('/renew_user/<username>', methods=['POST'])
def renew_user(username):
    add_gb = float(request.form.get('add_gb', 50)); add_days = int(request.form.get('add_days', 30))
    if os.path.exists(USERS_DB):
        with open(USERS_DB, 'r') as f: db = json.load(f)
        user = db.get(username)
        if user:
            user['total_gb'] = add_gb; user['days'] = add_days
            user['expire_date'] = (datetime.now() + timedelta(days=add_days)).strftime("%Y-%m-%d")
            user['used_bytes'] = 0; user['last_raw_bytes'] = 0; user['is_blocked'] = False
            with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(request.referrer)

@app.route('/delete_user/<username>', methods=['POST'])
def delete_user(username):
    if os.path.exists(USERS_DB):
        with open(USERS_DB, 'r') as f: db = json.load(f)
        if username in db:
            user = db[username]; nodes = get_nodes(); node_ip = nodes.get(user.get('node'))
            if node_ip:
                safe_cmd = get_safe_delete_cmd(username, user.get('protocol', 'v2'), user.get('port', '443'))
                os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"{safe_cmd} ; systemctl restart xray\"")
            del db[username]
            with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(request.referrer)

@app.route('/download_backup')
def download_backup():
    if os.path.exists(USERS_DB): return send_file(USERS_DB, as_attachment=True, download_name=f"qito_db_backup.json")
    return "No DB found."

@app.route('/upload_backup', methods=['POST'])
def upload_backup():
    file = request.files.get('backup_file')
    if file: file.save(USERS_DB)
    return redirect(url_for('dashboard'))

@app.route('/save_settings_basic', methods=['POST'])
def save_settings_basic():
    config = load_config()
    config['interval'] = int(request.form.get('interval', 12))
    config['bot_token'] = request.form.get('bot_token', '')
    save_config(config)
    return redirect(url_for('dashboard'))

@app.route('/config_action', methods=['POST'])
def config_action():
    config = load_config()
    ctype = request.form.get('type'); action = request.form.get('action')
    val = request.form.get('val', '').strip()
    target_list = 'admin_ids' if ctype == 'admin' else 'mod_ids'
    if action == 'add' and val:
        if val not in config[target_list]: config[target_list].append(val)
    elif action == 'del' and val:
        if val in config[target_list]: config[target_list].remove(val)
    save_config(config)
    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)
