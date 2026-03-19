from flask import Flask, render_template, request, redirect, session, url_for, send_file, jsonify
import json, os, subprocess, re, urllib.parse
from datetime import datetime, timedelta

from config import SECRET_KEY, USERS_DB, NODES_LIST, CONFIG_FILE, ADMIN_PASS, load_config, save_config
from utils import get_nodes, get_all_servers, check_live_status, db_lock, AUTO_GROUPS_FILE
from core_auto import load_auto_groups, save_auto_groups
from core_monitor import start_background_monitor
from core_actions import generate_keys, toggle_user_status, remove_user, bulk_remove_users, process_rebalance, run_bg

app = Flask(__name__)
app.secret_key = SECRET_KEY
BACKUP_DIR = "/root/PanelMaster/backups"
if not os.path.exists(BACKUP_DIR): os.makedirs(BACKUP_DIR)

start_background_monitor()

@app.before_request
def check_auth():
    if request.endpoint not in ['login', 'static', 'api_stats'] and not session.get('logged_in'): return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASS:
            session['logged_in'] = True; return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

def get_node_backups():
    backups = {}
    if os.path.exists(BACKUP_DIR):
        for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if f.endswith('.json') and f.startswith("backup_"):
                parts = f.split('_')
                if len(parts) >= 3:
                    nid = parts[1]
                    if nid not in backups: backups[nid] = []
                    path = os.path.join(BACKUP_DIR, f)
                    size = os.path.getsize(path) / 1024
                    ctime = datetime.fromtimestamp(os.path.getctime(path)).strftime('%Y-%m-%d %H:%M:%S')
                    backups[nid].append({"filename": f, "size": f"{size:.1f} KB", "time": ctime})
    return backups

@app.route('/')
def dashboard():
    nodes = get_nodes()
    auto_groups = load_auto_groups()
    db = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: pass
    config = load_config(); active_users = check_live_status(db); node_stats = []; group_stats = []
    
    for nid, info in nodes.items():
        total_count = sum(1 for i in db.values() if i.get('node') == nid and not i.get('group'))
        live_count = sum(1 for uname, i in db.items() if i.get('node') == nid and not i.get('group') and uname in active_users and not i.get('is_blocked'))
        node_stats.append({"id": nid, "name": info.get('name', nid), "ip": info.get('ip', ''), "total": total_count, "live": live_count, "disabled": nid in config.get('disabled_nodes', [])})
        
    for gid, gdata in auto_groups.items():
        limit = gdata.get("limit", 30)
        g_nodes = gdata.get("nodes", {})
        g_keys = sum(1 for i in db.values() if i.get("group") == gid)
        group_stats.append({"id": gid, "name": gdata.get("name", gid), "limit": limit, "node_count": len(g_nodes), "total_keys": g_keys})

    return render_template('dashboard.html', nodes=node_stats, groups=group_stats, config=config, backups=get_node_backups())

@app.route('/add_auto_group', methods=['POST'])
def add_auto_group():
    gid = request.form.get('group_id', '').strip().replace(" ", "_")
    gname = request.form.get('group_name', '').strip()
    limit = int(request.form.get('limit', 30))
    if gid and gname:
        groups = load_auto_groups()
        groups[gid] = {"name": gname, "limit": limit, "nodes": {}}
        save_auto_groups(groups)
    return redirect(url_for('dashboard'))

@app.route('/delete_auto_group/<group_id>', methods=['POST'])
def delete_auto_group(group_id):
    groups = load_auto_groups()
    if group_id in groups:
        del groups[group_id]
        save_auto_groups(groups)
    return redirect(url_for('dashboard'))

@app.route('/group/<group_id>')
def group_view(group_id):
    groups = load_auto_groups()
    if group_id not in groups: return redirect(url_for('dashboard'))
    group = groups[group_id]; db = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            
    active_users = check_live_status(db); users = []; server_stats = []
    g_nodes = group.get("nodes", {})
    counts = {nid: 0 for nid in g_nodes.keys()}
    
    for uname, info in db.items():
        if info.get('group') == group_id:
            info['used_bytes'] = float(info.get('used_bytes', 0)); info['total_gb'] = float(info.get('total_gb', 0)); info['used_gb_str'] = f"{(info['used_bytes'] / (1024**3)):.2f}"
            info['username'] = uname; info['actual_key'] = info.get('key') or "No Key Found"
            info['is_active'] = uname in active_users and not info.get('is_blocked')
            users.append(info)
            if info.get('node') in counts: counts[info.get('node')] += 1
            
    users = sorted(users, key=lambda x: (x.get('node', ''), x.get('username', '')))
    for idx, u in enumerate(users, start=1):
        u['global_key_idx'] = idx
            
    for nid, ndata in g_nodes.items():
        if isinstance(ndata, dict):
            nip = str(ndata.get("ip")).strip()
            limit = int(ndata.get("limit", group.get("limit", 30)))
        else:
            nip = str(ndata).strip()
            limit = int(group.get("limit", 30))
        server_stats.append({"id": nid, "ip": nip, "count": counts[nid], "limit": limit})
        
    return render_template('group.html', group_id=group_id, group=group, users=users, server_stats=server_stats)

@app.route('/add_server_to_group/<group_id>', methods=['POST'])
def add_server_to_group(group_id):
    nid = request.form.get('node_id', '').strip().replace(" ", "_")
    nip = request.form.get('node_ip', '').strip()
    limit = int(request.form.get('limit', 30))
    groups = load_auto_groups()
    if group_id in groups and nid and nip:
        groups[group_id]["nodes"][nid] = {"ip": nip, "limit": limit}
        save_auto_groups(groups)
    return redirect(f'/group/{group_id}?newly_added={nid}')

@app.route('/delete_server_from_group/<group_id>/<node_id>', methods=['POST'])
def delete_server_from_group(group_id, node_id):
    groups = load_auto_groups()
    node_ip = None
    if group_id in groups and node_id in groups[group_id]["nodes"]:
        ndata = groups[group_id]["nodes"][node_id]
        node_ip = str(ndata.get("ip")).strip() if isinstance(ndata, dict) else str(ndata).strip()
        del groups[group_id]["nodes"][node_id]
        save_auto_groups(groups)
        
    if node_ip:
        with db_lock:
            if os.path.exists(USERS_DB):
                with open(USERS_DB, 'r') as f: db = json.load(f)
                users_to_delete = [u for u, info in db.items() if info.get('node') == node_id]
                for u in users_to_delete:
                    remove_user(u)
    return redirect(f'/group/{group_id}')

@app.route('/edit_group_limit/<group_id>', methods=['POST'])
def edit_group_limit(group_id):
    new_limit = int(request.form.get('limit', 30))
    success, msg = process_rebalance(group_id, new_limit)
    if not success:
        return f"<script>alert('{msg}'); window.location.href='/group/{group_id}';</script>"
    return redirect(f'/group/{group_id}')

@app.route('/edit_server_limit/<group_id>/<node_id>', methods=['POST'])
def edit_server_limit(group_id, node_id):
    new_limit = int(request.form.get('limit', 30))
    success, msg = process_rebalance(group_id, new_limit, specific_node=node_id)
    if not success:
        return f"<script>alert('{msg}'); window.location.href='/group/{group_id}';</script>"
    return redirect(f'/group/{group_id}')

@app.route('/add_user_auto', methods=['POST'])
def add_user_auto():
    gid = request.form.get('group_id', '').strip()
    mode = request.form.get('creation_mode', 'single')
    
    raw_usernames = []
    if mode == 'single': raw_usernames = [request.form.get('single_username', '')]
    elif mode == 'list': raw_usernames = re.split(r'[,\n\r]+', request.form.get('list_usernames', ''))
    elif mode == 'pattern':
        base = request.form.get('base_name', '').strip()
        try: start = int(request.form.get('start_num') or 1)
        except: start = 1
        try: qty = int(request.form.get('qty') or 1)
        except: qty = 1
        raw_usernames = [f"{base}{start+i}" for i in range(qty)]

    try: gb = float(request.form.get('total_gb') or 0)
    except: gb = 0.0
    try: days = int(request.form.get('expire_days') or 30)
    except: days = 30
    
    proto = request.form.get('protocol', 'v2')

    success, msg = generate_keys(None, gid, raw_usernames, gb, days, proto, is_auto=True)
    if not success:
        return f"<script>alert('{msg}'); window.history.back();</script>"
    return redirect(f'/group/{gid}')

# 🚀 UPDATE: Custom Node အတွက် Key ထုတ်မည့် လမ်းကြောင်း (Error ကင်းစင်အောင် ပြင်ဆင်ပြီး)
@app.route('/add_user_manual', methods=['POST'])
def add_user_manual():
    nid = request.form.get('node_id', '').strip()
    nip = get_all_servers().get(nid, {}).get('ip')
    if not nip: return redirect(f'/node/{nid}')
    
    gid = ""
    groups = load_auto_groups()
    for g_id, gdata in groups.items():
        if nid in gdata.get("nodes", {}): gid = g_id; break

    mode = request.form.get('creation_mode', 'single')
    raw_usernames = []
    if mode == 'single': raw_usernames = [request.form.get('single_username', '')]
    elif mode == 'list': raw_usernames = re.split(r'[,\n\r]+', request.form.get('list_usernames', ''))
    elif mode == 'pattern':
        base = request.form.get('base_name', '').strip()
        try: start = int(request.form.get('start_num') or 1)
        except: start = 1
        try: qty = int(request.form.get('qty') or 1)
        except: qty = 1
        raw_usernames = [f"{base}{start+i}" for i in range(qty)]

    try: gb = float(request.form.get('total_gb') or 0)
    except: gb = 0.0
    try: days = int(request.form.get('expire_days') or 30)
    except: days = 30
    
    proto = request.form.get('protocol', 'v2')
    
    success, msg = generate_keys(nid, gid, raw_usernames, gb, days, proto, is_auto=False)
    if not success:
        return f"<script>alert('{msg}'); window.history.back();</script>"
    return redirect(f'/node/{nid}')

@app.route('/node/<node_id>')
def node_view(node_id):
    nodes = get_all_servers()
    if node_id not in nodes: return redirect(url_for('dashboard'))
    node_info = nodes[node_id]; db = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: pass
    config = load_config(); active_users = check_live_status(db); users = []
    for uname, info in db.items():
        if info.get('node') == node_id:
            info['used_bytes'] = float(info.get('used_bytes', 0)); info['total_gb'] = float(info.get('total_gb', 0)); info['used_gb_str'] = f"{(info['used_bytes'] / (1024**3)):.2f}"
            info['username'] = uname; info['actual_key'] = info.get('key') or "No Key Found"
            info['is_active'] = uname in active_users and not info.get('is_blocked')
            users.append(info)
    other_nodes = [nid for nid in nodes.keys() if nid != node_id]
    return render_template('node.html', node_id=node_id, node_name=node_info.get('name', ''), node_ip=node_info.get('ip', ''), users=users, other_nodes=other_nodes, config=config)

@app.route('/add_node', methods=['POST'])
def add_node():
    n_id = request.form.get('node_id', '').strip().replace(" ", "_")
    n_name = request.form.get('node_name', '').strip()
    n_ip = request.form.get('node_ip', '').strip()
    if n_id and n_name and n_ip:
        with open(NODES_LIST, 'a') as f: 
            f.write(f"\n{n_id}|{n_name}|{n_ip}")
    return redirect(url_for('node_view', node_id=n_id) + "?newly_added=yes")

@app.route('/delete_node/<node_id>', methods=['POST'])
def delete_node(node_id):
    nodes = get_all_servers()
    if node_id in nodes:
        node_ip = nodes[node_id].get('ip')
        if node_ip: run_bg(node_ip, "systemctl stop xray")
    
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f: lines = f.readlines()
        with open(NODES_LIST, 'w') as f:
            for line in lines:
                if line.strip() and not line.startswith(f"{node_id}|") and not line.startswith(f"{node_id} "): 
                    f.write(line)
                    
    groups = load_auto_groups()
    is_auto = False
    for gid, gdata in groups.items():
        if node_id in gdata.get("nodes", {}):
            del groups[gid]["nodes"][node_id]
            save_auto_groups(groups)
            is_auto = True
            break
            
    config = load_config()
    if node_id in config.get('disabled_nodes', []): config['disabled_nodes'].remove(node_id); save_config(config)
    
    if is_auto: return redirect(request.referrer)
    return redirect(url_for('dashboard'))

@app.route('/replace_id/<current_id>', methods=['POST'])
def replace_id(current_id):
    old_id = request.form.get('old_id', '').strip(); nodes = get_all_servers()
    if current_id not in nodes or not old_id: return redirect(f'/node/{current_id}')
    current_ip = str(nodes[current_id].get('ip')).strip()
    
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f: lines = f.readlines()
        with open(NODES_LIST, 'w') as f:
            for line in lines:
                if line.strip():
                    if line.startswith(f"{current_id}|") or line.startswith(f"{current_id} "):
                        if '|' in line:
                            parts = line.split('|')
                            f.write(f"{old_id}|{parts[1]}|{parts[2]}\n")
                        else:
                            parts = line.rsplit(' ', 1)
                            f.write(f"{old_id} {parts[1]}\n")
                    else: f.write(line)
                    
    groups = load_auto_groups()
    for gid, gdata in groups.items():
        if current_id in gdata.get("nodes", {}):
            ndata = gdata["nodes"][current_id]
            del groups[gid]["nodes"][current_id]
            groups[gid]["nodes"][old_id] = ndata
            save_auto_groups(groups)
            break
            
    commands = []
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            for uname, info in db.items():
                if info.get('node') == old_id:
                    if 'key' in info and current_ip: info['key'] = re.sub(r'(@)[^:]+(:)', f'\\g<1>{current_ip}\\g<2>', info['key'])
                    info['last_raw_bytes'] = 0; info['is_online'] = False
                    if not info.get('is_blocked', False):
                        uid = info.get('uuid'); port = str(info.get('port', '443'))
                        if info.get('protocol', 'v2') == 'v2': commands.append(f"/usr/local/bin/v2ray-node-add-vless {uname} {uid}")
                        else: commands.append(f"/usr/local/bin/v2ray-node-add-out {uname} {uid} {port} ; ufw allow {port}/tcp && ufw allow {port}/udp")
            with open(USERS_DB, 'w') as f: json.dump(db, f)
    if commands and current_ip:
        commands.append("systemctl restart xray")
        run_bg(current_ip, " ; ".join(commands))
    return redirect(f'/node/{old_id}')

@app.route('/api/check_ssh/<node_id>')
def check_ssh(node_id):
    ip = get_all_servers().get(node_id, {}).get('ip')
    if not ip: return jsonify({"status": "error"})
    try:
        res = subprocess.run(f"ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@{ip} 'echo ok'", shell=True, capture_output=True, text=True)
        if "ok" in res.stdout: return jsonify({"status": "success"})
    except: pass
    return jsonify({"status": "error"})

@app.route('/api/check_xray/<node_id>')
def check_xray(node_id):
    ip = get_all_servers().get(node_id, {}).get('ip')
    if not ip: return jsonify({"status": "inactive"})
    try:
        res = subprocess.run(f"ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@{ip} 'systemctl is-active xray'", shell=True, capture_output=True, text=True)
        if "active" in res.stdout.strip().lower(): return jsonify({"status": "active"})
    except: pass
    return jsonify({"status": "inactive"})

@app.route('/api/stats/<node_id>')
def api_stats(node_id):
    ip = get_all_servers().get(node_id, {}).get('ip')
    if not ip: return jsonify({"status": "error"})
    try:
        res = subprocess.run(f"ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no root@{ip} \"/usr/local/bin/xray api statsquery --server=127.0.0.1:10085\"", shell=True, capture_output=True, text=True)
        stats = json.loads(res.stdout).get("stat", [])
        data = {}
        for s in stats:
            p = s.get("name", "").split(">>>"); v = s.get("value", 0)
            if len(p) >= 4:
                if p[0] == "user": data[p[1]] = data.get(p[1], 0) + v
                elif p[0] == "inbound" and p[1].startswith("out-"): data[p[1][4:]] = data.get(p[1][4:], 0) + v
        return jsonify({"status": "ok", "data": data})
    except: return jsonify({"status": "error"})

@app.route('/install_node/<node_id>', methods=['POST'])
def install_node_action(node_id):
    ip = get_all_servers().get(node_id, {}).get('ip')
    if ip and os.path.exists("/root/PanelMaster/install_node.sh"):
        run_bg(ip, "bash -s < /root/PanelMaster/install_node.sh")
    return redirect(request.referrer)

@app.route('/toggle_node/<node_id>', methods=['POST'])
def toggle_node(node_id):
    config = load_config()
    if 'disabled_nodes' not in config: config['disabled_nodes'] = []
    ip = get_all_servers().get(node_id, {}).get('ip')
    if node_id in config['disabled_nodes']:
        config['disabled_nodes'].remove(node_id)
        if ip: run_bg(ip, "systemctl start xray")
    else:
        config['disabled_nodes'].append(node_id)
        if ip: run_bg(ip, "systemctl stop xray")
    save_config(config); return redirect(request.referrer)

@app.route('/toggle_user/<username>', methods=['POST'])
def toggle_user(username):
    toggle_user_status(username)
    return redirect(request.referrer)

@app.route('/edit_user/<username>', methods=['POST'])
def edit_user(username):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                try: db[username]['total_gb'] = float(request.form.get('total_gb', 0))
                except: pass
                db[username]['expire_date'] = request.form.get('expire_date', '')
                with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(request.referrer)

@app.route('/renew_user/<username>', methods=['POST'])
def renew_user(username):
    try: add_gb = float(request.form.get('add_gb') or 50)
    except: add_gb = 50.0
    try: add_days = int(request.form.get('add_days') or 30)
    except: add_days = 30
    
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                db[username]['total_gb'] = add_gb; db[username]['days'] = add_days
                db[username]['expire_date'] = (datetime.now() + timedelta(days=add_days)).strftime("%Y-%m-%d")
                db[username]['used_bytes'] = 0; db[username]['last_raw_bytes'] = 0; db[username]['is_blocked'] = False; db[username]['is_online'] = False
                with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(request.referrer)

@app.route('/delete_user/<username>', methods=['POST'])
def delete_user(username):
    remove_user(username)
    return redirect(request.referrer)

@app.route('/bulk_delete', methods=['POST'])
def bulk_delete():
    usernames = request.form.getlist('usernames')
    bulk_remove_users(usernames)
    return redirect(request.referrer)

@app.route('/create_node_backup/<node_id>', methods=['POST'])
def create_node_backup(node_id):
    if os.path.exists(USERS_DB):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"backup_{node_id}_{timestamp}.json"
        node_data = {}
        with db_lock:
            with open(USERS_DB, 'r') as f: db = json.load(f)
            for uname, info in db.items():
                if info.get('node') == node_id: node_data[uname] = info
        if node_data:
            with open(os.path.join(BACKUP_DIR, backup_name), 'w') as f: json.dump(node_data, f, indent=4)
    return redirect(request.referrer)

@app.route('/download_backup/<filename>')
def download_backup(filename):
    path = os.path.join(BACKUP_DIR, filename)
    if os.path.exists(path): return send_file(path, as_attachment=True)
    return redirect(request.referrer)

@app.route('/delete_backup/<filename>', methods=['POST'])
def delete_backup(filename):
    path = os.path.join(BACKUP_DIR, filename)
    if os.path.exists(path): os.remove(path)
    return redirect(request.referrer)

@app.route('/purge_node/<node_id>', methods=['POST'])
def purge_node(node_id):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            users_to_delete = [u for u, info in db.items() if info.get('node') == node_id]
            for u in users_to_delete: del db[u]
            with open(USERS_DB, 'w') as f: json.dump(db, f)
    if os.path.exists(BACKUP_DIR):
        for f in os.listdir(BACKUP_DIR):
            if f.startswith(f"backup_{node_id}_"): os.remove(os.path.join(BACKUP_DIR, f))
    return redirect(request.referrer)

@app.route('/download_backup_global')
def download_backup_global():
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
    config = load_config(); ctype = request.form.get('type'); action = request.form.get('action'); val = request.form.get('val', '').strip()
    target_list = 'admin_ids' if ctype == 'admin' else 'mod_ids'
    if action == 'add' and val:
        if val not in config.get(target_list, []): config.setdefault(target_list, []).append(val)
    elif action == 'del' and val:
        if val in config.get(target_list, []): config[target_list].remove(val)
    save_config(config)
    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)
