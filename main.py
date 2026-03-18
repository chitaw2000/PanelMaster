from flask import Flask, render_template, request, redirect, session, url_for, send_file, jsonify
import json, os, subprocess, uuid, base64, re, threading, time, shutil
from datetime import datetime, timedelta

from config import SECRET_KEY, USERS_DB, NODES_LIST, CONFIG_FILE, ADMIN_PASS, load_config, save_config
from utils import get_nodes, get_all_servers, check_live_status, get_safe_delete_cmd, db_lock, AUTO_GROUPS_FILE
from core_auto import load_auto_groups, save_auto_groups, find_available_node
from core_monitor import start_background_monitor

app = Flask(__name__)
app.secret_key = SECRET_KEY
BACKUP_DIR = "/root/PanelMaster/backups"
if not os.path.exists(BACKUP_DIR): os.makedirs(BACKUP_DIR)

# 🚀 နောက်ကွယ်မှ သေချာပေါက် ပိတ်ချမည့် Monitor ကို စတင်မည်
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
    
    # Custom Nodes တွက်ချက်ခြင်း
    for nid, info in nodes.items():
        total_count = sum(1 for i in db.values() if i.get('node') == nid and not i.get('group'))
        live_count = sum(1 for uname, i in db.items() if i.get('node') == nid and not i.get('group') and uname in active_users and not i.get('is_blocked'))
        node_stats.append({"id": nid, "name": info.get('name', nid), "ip": info.get('ip', ''), "total": total_count, "live": live_count, "disabled": nid in config.get('disabled_nodes', [])})
        
    # Auto Groups တွက်ချက်ခြင်း
    for gid, gdata in auto_groups.items():
        limit = gdata.get("limit", 30)
        g_nodes = gdata.get("nodes", {})
        g_keys = sum(1 for i in db.values() if i.get("group") == gid)
        group_stats.append({"id": gid, "name": gdata.get("name", gid), "limit": limit, "node_count": len(g_nodes), "total_keys": g_keys})

    return render_template('dashboard.html', nodes=node_stats, groups=group_stats, config=config, backups=get_node_backups())

# ==========================================
# 🚀 AUTO SERVER GROUPS ROUTES
# ==========================================
@app.route('/add_auto_group', methods=['POST'])
def add_auto_group():
    gid = request.form.get('group_id').strip().replace(" ", "_")
    gname = request.form.get('group_name').strip()
    limit = int(request.form.get('limit', 30))
    if gid and gname:
        groups = load_auto_groups()
        groups[gid] = {"name": gname, "limit": limit, "nodes": {}}
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
    
    # Group အတွင်းရှိ ဆာဗာများ၏ Key အရေအတွက်တွက်ချက်ခြင်း
    counts = {nid: 0 for nid in g_nodes.keys()}
    
    for uname, info in db.items():
        if info.get('group') == group_id:
            info['used_bytes'] = float(info.get('used_bytes', 0)); info['total_gb'] = float(info.get('total_gb', 0)); info['used_gb_str'] = f"{(info['used_bytes'] / (1024**3)):.2f}"
            info['username'] = uname; info['actual_key'] = info.get('key') or "No Key Found"
            info['is_active'] = uname in active_users and not info.get('is_blocked')
            users.append(info)
            if info.get('node') in counts: counts[info.get('node')] += 1
            
    for nid, nip in g_nodes.items():
        server_stats.append({"id": nid, "ip": nip, "count": counts[nid]})
        
    return render_template('group.html', group_id=group_id, group=group, users=users, server_stats=server_stats)

@app.route('/add_server_to_group/<group_id>', methods=['POST'])
def add_server_to_group(group_id):
    nid = request.form.get('node_id').strip().replace(" ", "_")
    nip = request.form.get('node_ip').strip()
    groups = load_auto_groups()
    if group_id in groups and nid and nip:
        groups[group_id]["nodes"][nid] = nip
        save_auto_groups(groups)
    return redirect(f'/group/{group_id}')

@app.route('/delete_server_from_group/<group_id>/<node_id>', methods=['POST'])
def delete_server_from_group(group_id, node_id):
    groups = load_auto_groups()
    if group_id in groups and node_id in groups[group_id]["nodes"]:
        del groups[group_id]["nodes"][node_id]
        save_auto_groups(groups)
    return redirect(f'/group/{group_id}')

@app.route('/add_user_auto', methods=['POST'])
def add_user_auto():
    gid = request.form.get('group_id')
    mode = request.form.get('creation_mode', 'single'); usernames = []
    if mode == 'single': usernames = [request.form.get('single_username', '').strip()]
    elif mode == 'list': usernames = [u.strip() for u in re.split(r'[,\n]+', request.form.get('list_usernames', '')) if u.strip()]
    elif mode == 'pattern':
        base = request.form.get('base_name', '').strip(); start = int(request.form.get('start_num', 1)); qty = int(request.form.get('qty', 1))
        usernames = [f"{base}{start+i}" for i in range(qty)]

    usernames = [u for u in usernames if u]
    if not usernames: return redirect(f'/group/{gid}')

    # 🚀 Load Balancer: နေရာလွတ်ရှိသော ဆာဗာကို အလိုအလျောက်ရှာဖွေခြင်း
    node_id, node_ip = find_available_node(gid, len(usernames))
    if not node_id:
        return "❌ Error: Not enough space in any Auto Server Node within this group. Please add more servers or increase the limit.", 400

    gb = float(request.form.get('total_gb', 0)); days = int(request.form.get('expire_days', 30))
    exp = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d"); proto = request.form.get('protocol', 'v2')
    
    db = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            
    max_p = max([int(i.get('port', 10000)) for i in db.values() if i.get('protocol') == 'out'] + [10000])
    cmds = []
    for u in usernames:
        if u in db: continue
        uid = str(uuid.uuid4())
        if proto == 'v2':
            port = "443"; k = f"vless://{uid}@{node_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{u}"
            cmds.append(f"/usr/local/bin/v2ray-node-add-vless {u} {uid}")
        else:
            max_p += 1; port = str(max_p); ss_conf = base64.b64encode(f"chacha20-ietf-poly1305:{uid}".encode()).decode()
            k = f"ss://{ss_conf}@{node_ip}:{port}#{u}"
            cmds.append(f"/usr/local/bin/v2ray-node-add-out {u} {uid} {port} ; ufw allow {port}/tcp && ufw allow {port}/udp")
        db[u] = {"node": node_id, "group": gid, "protocol": proto, "uuid": uid, "port": port, "total_gb": gb, "expire_date": exp, "used_bytes": 0, "last_raw_bytes": 0, "is_blocked": False, "is_online": False, "key": k}
    
    if cmds:
        with db_lock:
            with open(USERS_DB, 'w') as f: json.dump(db, f)
        subprocess.run(f"ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no root@{node_ip} \"{' ; '.join(cmds)}\"", shell=True)
        subprocess.run(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{node_ip} \"systemctl restart xray\"", shell=True)
    return redirect(f'/group/{gid}')

# ==========================================
# 🌐 CUSTOM NODES & GENERAL ROUTES
# ==========================================
@app.route('/node/<node_id>')
def node_view(node_id):
    nodes = get_nodes()
    if node_id not in nodes: return redirect(url_for('dashboard'))
    node_info = nodes[node_id]; db = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: pass
    config = load_config(); active_users = check_live_status(db); users = []
    for uname, info in db.items():
        if info.get('node') == node_id and not info.get('group'):
            info['used_bytes'] = float(info.get('used_bytes', 0)); info['total_gb'] = float(info.get('total_gb', 0)); info['used_gb_str'] = f"{(info['used_bytes'] / (1024**3)):.2f}"
            info['username'] = uname; info['actual_key'] = info.get('key') or "No Key Found"
            info['is_active'] = uname in active_users and not info.get('is_blocked')
            users.append(info)
    other_nodes = [nid for nid in nodes.keys() if nid != node_id]
    return render_template('node.html', node_id=node_id, node_name=node_info.get('name', ''), node_ip=node_info.get('ip', ''), users=users, other_nodes=other_nodes, config=config)

@app.route('/add_node', methods=['POST'])
def add_node():
    n_id = request.form.get('node_id').strip().replace(" ", "_"); n_name = request.form.get('node_name').strip(); n_ip = request.form.get('node_ip').strip()
    if n_id and n_name and n_ip:
        with open(NODES_LIST, 'a') as f: f.write(f"\n{n_id} {n_name} {n_ip}")
    return redirect(url_for('node_view', node_id=n_id) + "?newly_added=yes")

@app.route('/add_user_manual', methods=['POST'])
def add_user_manual():
    nid = request.form.get('node_id'); nip = get_nodes().get(nid, {}).get('ip')
    if not nip: return redirect(f'/node/{nid}')
    
    mode = request.form.get('creation_mode', 'single'); usernames = []
    if mode == 'single': usernames = [request.form.get('single_username', '').strip()]
    elif mode == 'list': usernames = [u.strip() for u in re.split(r'[,\n]+', request.form.get('list_usernames', '')) if u.strip()]
    elif mode == 'pattern':
        base = request.form.get('base_name', '').strip(); start = int(request.form.get('start_num', 1)); qty = int(request.form.get('qty', 1))
        usernames = [f"{base}{start+i}" for i in range(qty)]

    gb = float(request.form.get('total_gb', 0)); days = int(request.form.get('expire_days', 30))
    exp = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d"); proto = request.form.get('protocol', 'v2')
    
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
            port = "443"; k = f"vless://{uid}@{nip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{u}"
            cmds.append(f"/usr/local/bin/v2ray-node-add-vless {u} {uid}")
        else:
            max_p += 1; port = str(max_p); ss_conf = base64.b64encode(f"chacha20-ietf-poly1305:{uid}".encode()).decode()
            k = f"ss://{ss_conf}@{nip}:{port}#{u}"
            cmds.append(f"/usr/local/bin/v2ray-node-add-out {u} {uid} {port} ; ufw allow {port}/tcp && ufw allow {port}/udp")
        db[u] = {"node": nid, "protocol": proto, "uuid": uid, "port": port, "total_gb": gb, "expire_date": exp, "used_bytes": 0, "last_raw_bytes": 0, "is_blocked": False, "is_online": False, "key": k}
    
    if cmds:
        with db_lock:
            with open(USERS_DB, 'w') as f: json.dump(db, f)
        subprocess.run(f"ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no root@{nip} \"{' ; '.join(cmds)}\"", shell=True)
        subprocess.run(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{nip} \"systemctl restart xray\"", shell=True)
    return redirect(f'/node/{nid}')

@app.route('/toggle_user/<username>', methods=['POST'])
def toggle_user(username):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                user = db[username]; user['is_blocked'] = not user.get('is_blocked', False)
                ip = get_all_servers().get(user.get('node'), {}).get('ip')
                if ip:
                    if user['is_blocked']: 
                        user['is_online'] = False
                        cmd = get_safe_delete_cmd(username, user.get('protocol', 'v2'), user.get('port', '443'))
                    else:
                        uid = user['uuid']
                        if user['protocol'] == 'v2': cmd = f"/usr/local/bin/v2ray-node-add-vless {username} {uid}"
                        else: cmd = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {user['port']}"
                    subprocess.run(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{ip} \"{cmd}\"", shell=True)
                    subprocess.run(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{ip} \"systemctl restart xray\"", shell=True)
                with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(request.referrer)

@app.route('/edit_user/<username>', methods=['POST'])
def edit_user(username):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                db[username]['total_gb'] = float(request.form.get('total_gb', 0))
                db[username]['expire_date'] = request.form.get('expire_date', '')
                with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(request.referrer)

@app.route('/renew_user/<username>', methods=['POST'])
def renew_user(username):
    add_gb = float(request.form.get('add_gb', 50)); add_days = int(request.form.get('add_days', 30))
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
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                info = db[username]; ip = get_all_servers().get(info.get('node'), {}).get('ip')
                if ip:
                    cmd = get_safe_delete_cmd(username, info.get('protocol', 'v2'), info.get('port', '443'))
                    subprocess.run(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{ip} \"{cmd}\"", shell=True)
                    subprocess.run(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{ip} \"systemctl restart xray\"", shell=True)
                del db[username]
                with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(request.referrer)

@app.route('/bulk_delete', methods=['POST'])
def bulk_delete():
    usernames = request.form.getlist('usernames')
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            nodes = get_all_servers()
            for uname in usernames:
                if uname in db:
                    ip = nodes.get(db[uname].get('node'), {}).get('ip')
                    if ip:
                        cmd = get_safe_delete_cmd(uname, db[uname].get('protocol', 'v2'), db[uname].get('port', '443'))
                        subprocess.run(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{ip} \"{cmd}\"", shell=True)
                        subprocess.run(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{ip} \"systemctl restart xray\"", shell=True)
                    del db[uname]
            with open(USERS_DB, 'w') as f: json.dump(db, f)
    return redirect(request.referrer)

# (တခြားသော Backup, Purge နှင့် API Routes များသည် အရင်အတိုင်း ဆက်ရှိနေပါမည်။ နေရာအခက်အခဲကြောင့် မူရင်းအတိုင်း ဆက်လက်အသုံးပြုပေးပါရန်)
# ဥပမာ - /delete_node, /replace_id, /purge_node, /api/stats, etc.
