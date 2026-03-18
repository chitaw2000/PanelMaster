from flask import Flask, render_template, request, redirect, session, url_for, send_file, jsonify
import json, os, subprocess, uuid, base64, re, threading, time, shutil
from datetime import datetime, timedelta

from config import SECRET_KEY, USERS_DB, NODES_LIST, CONFIG_FILE, ADMIN_PASS, load_config, save_config
from utils import get_nodes, check_live_status, get_safe_delete_cmd

app = Flask(__name__)
app.secret_key = SECRET_KEY

db_lock = threading.Lock()
BACKUP_DIR = "/root/PanelMaster/backups"

if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

# =========================================================
# 🚀 BACKGROUND TRAFFIC MONITOR
# =========================================================
def background_traffic_monitor():
    while True:
        time.sleep(30)
        try:
            nodes = get_nodes()
            if not nodes: continue
            
            with db_lock:
                if not os.path.exists(USERS_DB): continue
                with open(USERS_DB, 'r') as f: db = json.load(f)
            
            if not db: continue
            db_changed = False
            
            for node_id, info in nodes.items():
                node_ip = info.get('ip')
                if not node_ip: continue
                try:
                    cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"/usr/local/bin/xray api statsquery --server=127.0.0.1:10085\""
                    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    if res.stdout.strip():
                        stats = json.loads(res.stdout).get("stat", [])
                        user_bytes = {}
                        
                        for s in stats:
                            parts = s.get("name", "").split(">>>")
                            val = s.get("value", 0)
                            if len(parts) >= 4:
                                if parts[0] == "user":
                                    uname = parts[1]
                                    user_bytes[uname] = user_bytes.get(uname, 0) + val
                                elif parts[0] == "inbound" and parts[1].startswith("out-"):
                                    uname = parts[1][4:]
                                    user_bytes[uname] = user_bytes.get(uname, 0) + val
                                    
                        for uname, val in user_bytes.items():
                            if uname in db and db[uname].get("node") == node_id:
                                last_raw = db[uname].get('last_raw_bytes', 0)
                                if val < last_raw:
                                    db[uname]['used_bytes'] = db[uname].get('used_bytes', 0) + val
                                else:
                                    db[uname]['used_bytes'] = db[uname].get('used_bytes', 0) + (val - last_raw)
                                
                                db[uname]['last_raw_bytes'] = val
                                db_changed = True
                                
                                tot_gb = float(db[uname].get('total_gb', 0))
                                if tot_gb > 0:
                                    max_bytes = tot_gb * (1024**3)
                                    if float(db[uname]['used_bytes']) >= max_bytes and not db[uname].get('is_blocked', False):
                                        db[uname]['is_blocked'] = True
                                        safe_cmd = get_safe_delete_cmd(uname, db[uname].get('protocol', 'v2'), db[uname].get('port', '443'))
                                        os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"{safe_cmd} ; systemctl restart xray\" &")
                except Exception:
                    pass
            
            if db_changed:
                with db_lock:
                    with open(USERS_DB, 'w') as f: json.dump(db, f)
        except Exception:
            pass

monitor_thread = threading.Thread(target=background_traffic_monitor, daemon=True)
monitor_thread.start()

# =========================================================
# 🌐 ROUTES
# =========================================================
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

def get_node_backups():
    backups = {}
    if os.path.exists(BACKUP_DIR):
        for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if f.endswith('.json'):
                parts = f.split('_')
                if len(parts) >= 3 and parts[0] == "backup":
                    nid = parts[1]
                    if nid not in backups:
                        backups[nid] = []
                    backups[nid].append(f)
    return backups

@app.route('/')
def dashboard():
    nodes = get_nodes()
    db = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: pass
        
    config = load_config()
    active_users = check_live_status(db)
    
    node_stats = []
    all_users = [] # HTML Error မတက်စေရန် ပြန်ထည့်ပေးထားသည်
    
    for nid, info in nodes.items():
        total_count = 0
        live_count = 0
        for uname, i in db.items():
            if i.get('node') == nid:
                total_count += 1
                if uname in active_users and not i.get('is_blocked'):
                    live_count += 1
                all_users.append({'username': uname, 'node': nid, 'key': i.get('key', 'No Key')})
                
        node_stats.append({
            "id": nid, 
            "name": info.get('name', nid), 
            "ip": info.get('ip', ''), 
            "total": total_count, 
            "live": live_count, 
            "disabled": nid in config.get('disabled_nodes', [])
        })
        
    # config နှင့် all_users ကိုပါ ပြန်ထည့်ပေးထားသည်
    return render_template('dashboard.html', nodes=node_stats, all_users=all_users, config=config, backups=get_node_backups())

@app.route('/node/<node_id>')
def node_view(node_id):
    nodes = get_nodes()
    if node_id not in nodes:
        return redirect(url_for('dashboard'))
    
    node_info = nodes[node_id]
    db = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: pass
            
    config = load_config()
    active_users = check_live_status(db)
    users = []
    for uname, info in db.items():
        if info.get('node') == node_id:
            info['used_bytes'] = float(info.get('used_bytes', 0))
            info['total_gb'] = float(info.get('total_gb', 0))
            info['used_gb_str'] = f"{(info['used_bytes'] / (1024**3)):.2f}"
            info['username'] = uname
            info['actual_key'] = info.get('key') or "No Key Found"
            info['is_active'] = uname in active_users and not info.get('is_blocked')
            info['is_blocked'] = info.get('is_blocked', False)
            users.append(info)
            
    other_nodes = [nid for nid in nodes.keys() if nid != node_id]
            
    return render_template('node.html', node_id=node_id, node_name=node_info.get('name', ''), node_ip=node_info.get('ip', ''), users=users, other_nodes=other_nodes, backups=get_node_backups(), config=config)

@app.route('/add_node', methods=['POST'])
def add_node():
    n_id = request.form.get('node_id').strip().replace(" ", "_")
    n_name = request.form.get('node_name').strip().replace(" ", "_")
    n_ip = request.form.get('node_ip').strip()
    if n_id and n_name and n_ip:
        with open(NODES_LIST, 'a') as f: 
            f.write(f"\n{n_id} {n_name} {n_ip}")
    return redirect(url_for('node_view', node_id=n_id) + "?newly_added=yes")

@app.route('/delete_node/<node_id>', methods=['POST'])
def delete_node(node_id):
    nodes = get_nodes()
    if node_id in nodes:
        node_ip = nodes[node_id].get('ip')
        if node_ip:
            os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} 'systemctl stop xray' &")
        
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f: lines = f.readlines()
        with open(NODES_LIST, 'w') as f:
            for line in lines:
                if line.strip() and line.split()[0] != node_id: 
                    f.write(line)
    
    config = load_config()
    if node_id in config.get('disabled_nodes', []):
        config['disabled_nodes'].remove(node_id)
        save_config(config)

    return redirect(url_for('dashboard'))

@app.route('/replace_id/<current_id>', methods=['POST'])
def replace_id(current_id):
    old_id = request.form.get('old_id').strip()
    nodes = get_nodes()
    
    if current_id not in nodes or not old_id: 
        return redirect(f'/node/{current_id}')
    
    current_ip = nodes[current_id].get('ip')
    
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f: lines = f.readlines()
        with open(NODES_LIST, 'w') as f:
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if parts[0] == current_id:
                        f.write(f"{old_id} {parts[1]} {parts[2]}\n")
                    else:
                        f.write(line)
                        
    commands = []
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            for uname, info in db.items():
                if info.get('node') == old_id:
                    if 'key' in info and current_ip:
                        info['key'] = re.sub(r'(@)[^:]+(:)', f'\\g<1>{current_ip}\\g<2>', info['key'])
                    info['last_raw_bytes'] = 0
                    
                    if not info.get('is_blocked', False):
                        uid = info.get('uuid')
                        port = str(info.get('port', '443'))
                        if info.get('protocol', 'v2') == 'v2': 
                            commands.append(f"/usr/local/bin/v2ray-node-add-vless {uname} {uid}")
                        else: 
                            commands.append(f"/usr/local/bin/v2ray-node-add-out {uname} {uid} {port} ; ufw allow {port}/tcp && ufw allow {port}/udp")
            with open(USERS_DB, 'w') as f: json.dump(db, f)

    if commands and current_ip:
        commands.append("systemctl restart xray")
        os.system(f"ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no root@{current_ip} \"{' ; '.join(commands)}\" &")

    return redirect(f'/node/{old_id}')

@app.route('/create_node_backup/<node_id>', methods=['POST'])
def create_node_backup(node_id):
    if os.path.exists(USERS_DB):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"backup_{node_id}_{timestamp}.json"
        
        node_data = {}
        with db_lock:
            with open(USERS_DB, 'r') as f: db = json.load(f)
            for uname, info in db.items():
                if info.get('node') == node_id: 
                    node_data[uname] = info
                
        if node_data:
            with open(os.path.join(BACKUP_DIR, backup_name), 'w') as f: 
                json.dump(node_data, f, indent=4)
    return redirect(request.referrer)

@app.route('/download_backup/<filename>')
def download_backup(filename):
    path = os.path.join(BACKUP_DIR, filename)
    if os.path.exists(path): 
        return send_file(path, as_attachment=True)
    return redirect(request.referrer)

@app.route('/api/check_ssh/<node_id>')
def check_ssh(node_id):
    nodes = get_nodes()
    ip = nodes.get(node_id, {}).get('ip')
    if not ip: return jsonify({"status": "error"})
    try:
        res = subprocess.run(f"ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@{ip} 'echo ok'", shell=True, capture_output=True, text=True)
        if "ok" in res.stdout: return jsonify({"status": "success"})
    except: pass
    return jsonify({"status": "error"})

@app.route('/api/check_xray/<node_id>')
def check_xray(node_id):
    nodes = get_nodes()
    ip = nodes.get(node_id, {}).get('ip')
    if not ip: return jsonify({"status": "inactive"})
    try:
        res = subprocess.run(f"ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@{ip} 'systemctl is-active xray'", shell=True, capture_output=True, text=True)
        if "active" in res.stdout.strip().lower(): return jsonify({"status": "active"})
    except: pass
    return jsonify({"status": "inactive"})

@app.route('/api/stats/<node_id>')
def api_stats(node_id):
    nodes = get_nodes()
    ip = nodes.get(node_id, {}).get('ip')
    if not ip: return jsonify({"status": "error"})
    try:
        res = subprocess.run(f"ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no root@{ip} \"/usr/local/bin/xray api statsquery --server=127.0.0.1:10085\"", shell=True, capture_output=True, text=True)
        stats = json.loads(res.stdout).get("stat", [])
        data = {}
        for s in stats:
            p = s.get("name", "").split(">>>")
            v = s.get("value", 0)
            if len(p) >= 4:
                if p[0] == "user": 
                    data[p[1]] = data.get(p[1], 0) + v
                elif p[0] == "inbound" and p[1].startswith("out-"): 
                    data[p[1][4:]] = data.get(p[1][4:], 0) + v
        return jsonify({"status": "ok", "data": data})
    except: 
        return jsonify({"status": "error"})

@app.route('/install_node/<node_id>', methods=['POST'])
def install_node_action(node_id):
    nodes = get_nodes()
    ip = nodes.get(node_id, {}).get('ip')
    if ip and os.path.exists("/root/PanelMaster/install_node.sh"):
        os.system(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{ip} 'bash -s' < /root/PanelMaster/install_node.sh")
    return redirect(f'/node/{node_id}')

@app.route('/toggle_node/<node_id>', methods=['POST'])
def toggle_node(node_id):
    config = load_config()
    if 'disabled_nodes' not in config: config['disabled_nodes'] = []
    
    nodes = get_nodes()
    node_ip = nodes.get(node_id, {}).get('ip')
    
    if node_id in config['disabled_nodes']:
        config['disabled_nodes'].remove(node_id)
        if node_ip: os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} 'systemctl start xray' &")
    else:
        config['disabled_nodes'].append(node_id)
        if node_ip: os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} 'systemctl stop xray' &")
    save_config(config)
    return redirect(f'/node/{node_id}')

@app.route('/add_user_manual', methods=['POST'])
def add_user_manual():
    nid = request.form.get('node_id')
    nodes = get_nodes()
    nip = nodes.get(nid, {}).get('ip')
    if not nip: return redirect(f'/node/{nid}')
    
    mode = request.form.get('creation_mode', 'single')
    usernames = []
    if mode == 'single': 
        usernames = [request.form.get('single_username', '').strip()]
    elif mode == 'list': 
        usernames = [u.strip() for u in re.split(r'[,\n]+', request.form.get('list_usernames', '')) if u.strip()]
    elif mode == 'pattern':
        base = request.form.get('base_name', '').strip()
        start = int(request.form.get('start_num', 1))
        qty = int(request.form.get('qty', 1))
        usernames = [f"{base}{start+i}" for i in range(qty)]

    gb = float(request.form.get('total_gb', 0))
    days = int(request.form.get('expire_days', 30))
    exp = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
    proto = request.form.get('protocol', 'v2')
    
    db = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            
    max_p = max([int(i.get('port', 10000)) for i in db.values() if i.get('protocol') == 'out'] + [10000])
    
    cmds = []
    for u in usernames:
        if u in db or not u: continue
        uid = str(uuid.uuid4())
        if proto == 'v2':
            port = "443"
            k = f"vless://{uid}@{nip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{u}"
            cmds.append(f"/usr/local/bin/v2ray-node-add-vless {u} {uid}")
        else:
            max_p += 1
            port = str(max_p)
            ss_conf = base64.b64encode(f"chacha20-ietf-poly1305:{uid}".encode()).decode()
            k = f"ss://{ss_conf}@{nip}:{port}#{u}"
            cmds.append(f"/usr/local/bin/v2ray-node-add-out {u} {uid} {port} ; ufw allow {port}/tcp && ufw allow {port}/udp")
            
        db[u] = {"node": nid, "protocol": proto, "uuid": uid, "port": port, "total_gb": gb, "expire_date": exp, "used_bytes": 0, "last_raw_bytes": 0, "is_blocked": False, "key": k}
    
    if cmds:
        with db_lock:
            with open(USERS_DB, 'w') as f: json.dump(db, f)
        os.system(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{nip} \"{' ; '.join(cmds)} ; systemctl restart xray\" &")
        
    return redirect(f'/node/{nid}')

@app.route('/toggle_user/<username>', methods=['POST'])
def toggle_user(username):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                user = db[username]
                user['is_blocked'] = not user.get('is_blocked', False)
                nodes = get_nodes()
                ip = nodes.get(user.get('node'), {}).get('ip')
                if ip:
                    if user['is_blocked']:
                        cmd = get_safe_delete_cmd(username, user.get('protocol', 'v2'), user.get('port', '443'))
                        os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{ip} \"{cmd}\" &")
                    else:
                        uid = user['uuid']
                        if user['protocol'] == 'v2': 
                            os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{ip} '/usr/local/bin/v2ray-node-add-vless {username} {uid} ; systemctl restart xray' &")
                        else: 
                            os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{ip} '/usr/local/bin/v2ray-node-add-out {username} {uid} {user['port']} ; systemctl restart xray' &")
                with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(request.referrer)

@app.route('/edit_user/<username>', methods=['POST'])
def edit_user(username):
    new_gb = float(request.form.get('total_gb', 0))
    new_date = request.form.get('expire_date', '')
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                db[username]['total_gb'] = new_gb
                db[username]['expire_date'] = new_date
                with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(request.referrer)

@app.route('/renew_user/<username>', methods=['POST'])
def renew_user(username):
    add_gb = float(request.form.get('add_gb', 50))
    add_days = int(request.form.get('add_days', 30))
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                db[username]['total_gb'] = add_gb
                db[username]['days'] = add_days
                db[username]['expire_date'] = (datetime.now() + timedelta(days=add_days)).strftime("%Y-%m-%d")
                db[username]['used_bytes'] = 0
                db[username]['last_raw_bytes'] = 0
                db[username]['is_blocked'] = False
                with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(request.referrer)

@app.route('/delete_user/<username>', methods=['POST'])
def delete_user(username):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                info = db[username]
                nodes = get_nodes()
                ip = nodes.get(info.get('node'), {}).get('ip')
                if ip:
                    cmd = get_safe_delete_cmd(username, info.get('protocol', 'v2'), info.get('port', '443'))
                    os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{ip} \"{cmd} ; systemctl restart xray\" &")
                del db[username]
                with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(request.referrer)

@app.route('/bulk_delete', methods=['POST'])
def bulk_delete():
    usernames = request.form.getlist('usernames')
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            nodes = get_nodes()
            
            for uname in usernames:
                if uname in db:
                    info = db[uname]
                    ip = nodes.get(info.get('node'), {}).get('ip')
                    if ip:
                        cmd = get_safe_delete_cmd(uname, info.get('protocol', 'v2'), info.get('port', '443'))
                        os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{ip} \"{cmd} ; systemctl restart xray\" &")
                    del db[uname]
            with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(request.referrer)

@app.route('/backups')
def backups_page():
    backups = []
    if os.path.exists(BACKUP_DIR):
        for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if f.endswith('.json') and not f.startswith('backup_'):
                path = os.path.join(BACKUP_DIR, f)
                size = os.path.getsize(path) / 1024
                ctime = datetime.fromtimestamp(os.path.getctime(path)).strftime('%Y-%m-%d %H:%M:%S')
                backups.append({"name": f, "size": f"{size:.1f} KB", "time": ctime})
    return render_template('backups.html', backups=backups)

@app.route('/create_backup', methods=['POST'])
def create_backup():
    if os.path.exists(USERS_DB):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"users_db_{timestamp}.json"
        shutil.copy2(USERS_DB, os.path.join(BACKUP_DIR, backup_name))
    return redirect(url_for('backups_page'))

@app.route('/download_backup_file/<filename>')
def download_backup_file(filename):
    file_path = os.path.join(BACKUP_DIR, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return redirect(url_for('backups_page'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)
