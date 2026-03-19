from flask import Flask, render_template, request, redirect, session, url_for, send_file, jsonify
import json, os, subprocess, uuid, base64, re, threading, time, urllib.parse
from datetime import datetime, timedelta

from config import SECRET_KEY, USERS_DB, NODES_LIST, CONFIG_FILE, ADMIN_PASS, load_config, save_config
from utils import get_nodes, get_all_servers, check_live_status, get_safe_delete_cmd, db_lock, AUTO_GROUPS_FILE

app = Flask(__name__)
app.secret_key = SECRET_KEY
BACKUP_DIR = "/root/PanelMaster/backups"
if not os.path.exists(BACKUP_DIR): os.makedirs(BACKUP_DIR)

try:
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            db_changed = False
            existing_ids = [int(u.get('key_id', 0)) for u in db.values() if isinstance(u, dict) and str(u.get('key_id', '')).isdigit()]
            next_id = max(existing_ids) + 1 if existing_ids else 1
            for uname in sorted(db.keys()):
                if 'key_id' not in db[uname]:
                    db[uname]['key_id'] = next_id
                    next_id += 1
                    db_changed = True
            if db_changed:
                with open(USERS_DB, 'w') as f: json.dump(db, f)
except Exception: pass

# ==========================================
# 🚀 100% BUG-FREE BACKGROUND SSH EXECUTION
# ==========================================
def _ssh_worker(ip, cmd_str):
    subprocess.run(f"ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no root@{ip} \"{cmd_str}\"", shell=True)

def execute_ssh_bg(ip, cmds):
    if not cmds: return
    cmd_str = " ; ".join(cmds)
    # 🚀 `&` အစား Python Thread ကိုအသုံးပြု၍ SSH Connection အား အဆုံးထိ သေချာပေါက် စောင့်၍ Run မည် (UI လည်းမ Hang ပါ)
    threading.Thread(target=_ssh_worker, args=(ip, cmd_str), daemon=True).start()

# ==========================================
# 🚀 AUTO GROUPS HELPER FUNCTIONS
# ==========================================
def load_auto_groups():
    if not os.path.exists(AUTO_GROUPS_FILE): return {}
    try:
        with open(AUTO_GROUPS_FILE, 'r') as f: return json.load(f)
    except: return {}

def save_auto_groups(data):
    with open(AUTO_GROUPS_FILE, 'w') as f: json.dump(data, f, indent=4)

def find_available_node(group_id, required_qty, current_db=None):
    groups = load_auto_groups()
    if group_id not in groups: return None, None
    group = groups[group_id]
    nodes = group.get("nodes", {})
    if not nodes: return None, None

    if current_db is not None: db = current_db
    else:
        with db_lock:
            if os.path.exists(USERS_DB):
                with open(USERS_DB, 'r') as f: db = json.load(f)
            else: db = {}

    counts = {nid: 0 for nid in nodes.keys()}
    for uname, uinfo in db.items():
        nid = uinfo.get("node")
        if nid in counts: counts[nid] += 1

    for nid in sorted(nodes.keys()):
        ndata = nodes[nid]
        if isinstance(ndata, dict):
            limit = int(ndata.get("limit", group.get("limit", 30)))
            nip = str(ndata.get("ip")).strip()
        else:
            limit = int(group.get("limit", 30))
            nip = str(ndata).strip()
            
        if counts[nid] + required_qty <= limit:
            return nid, nip
    return None, None

def sanitize_usernames(raw_list):
    clean = []
    for u in raw_list:
        if not u: continue
        u = str(u).strip().replace(" ", "_").replace("\r", "").replace("\n", "")
        if u: clean.append(u)
    return clean

# ==========================================
# 🚀 THE ULTIMATE BACKGROUND TRAFFIC MONITOR
# ==========================================
def background_traffic_monitor():
    while True:
        time.sleep(20)
        try:
            nodes = get_all_servers()
            if not nodes: continue
            
            gathered_stats = {}
            for node_id, info in nodes.items():
                node_ip = info.get('ip')
                if not node_ip: continue
                try:
                    cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"/usr/local/bin/xray api statsquery --server=127.0.0.1:10085\""
                    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    user_bytes = {}
                    if res.stdout.strip():
                        stats = json.loads(res.stdout).get("stat", [])
                        for s in stats:
                            parts = s.get("name", "").split(">>>")
                            val = s.get("value", 0)
                            if len(parts) >= 4:
                                if parts[0] == "user": user_bytes[parts[1]] = user_bytes.get(parts[1], 0) + val
                                elif parts[0] == "inbound" and parts[1].startswith("out-"): user_bytes[parts[1][4:]] = user_bytes.get(parts[1][4:], 0) + val
                    gathered_stats[node_id] = user_bytes
                except: pass

            if not gathered_stats: continue

            users_to_block = []
            with db_lock:
                if not os.path.exists(USERS_DB): continue
                with open(USERS_DB, 'r') as f: db = json.load(f)
                
                db_changed = False
                for uname, uinfo in db.items():
                    node_id = uinfo.get("node")
                    if node_id in gathered_stats:
                        user_bytes = gathered_stats[node_id]
                        val = user_bytes.get(uname, uinfo.get('last_raw_bytes', 0))
                        last_raw = uinfo.get('last_raw_bytes', 0)
                        
                        if val > last_raw: uinfo['is_online'] = True
                        else: uinfo['is_online'] = False
                            
                        if val < last_raw: uinfo['used_bytes'] = uinfo.get('used_bytes', 0) + val
                        else: uinfo['used_bytes'] = uinfo.get('used_bytes', 0) + (val - last_raw)
                        
                        uinfo['last_raw_bytes'] = val
                        db_changed = True
                        
                        tot_gb = float(uinfo.get('total_gb', 0))
                        if tot_gb > 0:
                            max_bytes = tot_gb * (1024**3)
                            if float(uinfo['used_bytes']) >= max_bytes and not uinfo.get('is_blocked', False):
                                uinfo['is_blocked'] = True
                                uinfo['is_online'] = False
                                node_ip = nodes.get(node_id, {}).get('ip')
                                if node_ip:
                                    users_to_block.append((node_ip, uname, uinfo.get('protocol', 'v2'), uinfo.get('port', '443')))
                
                if db_changed:
                    with open(USERS_DB, 'w') as f: json.dump(db, f)

            # 🚀 GB ပြည့်ပါက သေချာပေါက် ပိတ်ချမည်
            for node_ip, uname, proto, port in users_to_block:
                safe_cmd = get_safe_delete_cmd(uname, proto, port)
                execute_ssh_bg(node_ip, [safe_cmd, "systemctl restart xray"])
                
        except: pass

threading.Thread(target=background_traffic_monitor, daemon=True).start()

# ==========================================
# 🌐 WEB ROUTES
# ==========================================
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
                cmds = []
                for u in users_to_delete:
                    info = db[u]
                    cmds.append(get_safe_delete_cmd(u, info.get('protocol', 'v2'), info.get('port', '443')))
                    del db[u]
                if users_to_delete:
                    with open(USERS_DB, 'w') as f: json.dump(db, f)
                    cmds.append("systemctl restart xray")
                    execute_ssh_bg(node_ip, cmds)
    return redirect(f'/group/{group_id}')

@app.route('/edit_group_limit/<group_id>', methods=['POST'])
def edit_group_limit(group_id):
    new_limit = int(request.form.get('limit', 30))
    groups = load_auto_groups()
    if group_id not in groups: return redirect(url_for('dashboard'))

    groups[group_id]["limit"] = new_limit
    for nid in groups[group_id]["nodes"]:
        if isinstance(groups[group_id]["nodes"][nid], dict):
            groups[group_id]["nodes"][nid]["limit"] = new_limit
        else:
            groups[group_id]["nodes"][nid] = {"ip": groups[group_id]["nodes"][nid], "limit": new_limit}
    save_auto_groups(groups)

    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)

        excess_users = []
        for nid, ndata in groups[group_id]["nodes"].items():
            users_on_node = [uname for uname, info in db.items() if info.get('node') == nid]
            if len(users_on_node) > new_limit:
                excess_users.extend(users_on_node[new_limit:])

        if not excess_users:
            return redirect(f'/group/{group_id}')

        cmds_by_ip = {}
        migrated_count = 0
        
        for uname in excess_users:
            uinfo = db[uname]
            old_node = uinfo.get('node')
            old_ip = get_all_servers().get(old_node, {}).get('ip')
            old_port = uinfo.get('port')
            proto = uinfo.get('protocol')
            old_key_id = uinfo.get('key_id')
            
            new_node_id, new_node_ip = find_available_node(group_id, 1, current_db=db)
            if not new_node_id: break

            cmd_del = get_safe_delete_cmd(uname, proto, old_port)
            if old_ip not in cmds_by_ip: cmds_by_ip[old_ip] = []
            cmds_by_ip[old_ip].append(cmd_del)

            used_ports = [int(i.get('port', 10000)) for i in db.values() if i.get('protocol') == 'out' and i.get('node') == new_node_id]
            new_port = str(max(used_ports) + 1) if used_ports else "10001"

            uid = uinfo.get('uuid')
            safe_u = urllib.parse.quote(uname)

            if proto == 'v2':
                new_port = "443"
                k = f"vless://{uid}@{new_node_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
                cmd_add = f"/usr/local/bin/v2ray-node-add-vless {uname} {uid}"
            else:
                ss_conf = base64.b64encode(f"chacha20-ietf-poly1305:{uid}".encode()).decode()
                k = f"ss://{ss_conf}@{new_node_ip}:{new_port}#{safe_u}"
                cmd_add = f"/usr/local/bin/v2ray-node-add-out {uname} {uid} {new_port} ; ufw allow {new_port}/tcp && ufw allow {new_port}/udp"

            if new_node_ip not in cmds_by_ip: cmds_by_ip[new_node_ip] = []
            cmds_by_ip[new_node_ip].append(cmd_add)

            db[uname]['node'] = new_node_id
            db[uname]['port'] = new_port
            db[uname]['key'] = k
            if old_key_id: db[uname]['key_id'] = old_key_id
            migrated_count += 1

        with open(USERS_DB, 'w') as f: json.dump(db, f)

        for ip, cmds in cmds_by_ip.items():
            cmds.append("systemctl restart xray")
            execute_ssh_bg(ip, cmds)

    return redirect(f'/group/{group_id}')

@app.route('/edit_server_limit/<group_id>/<node_id>', methods=['POST'])
def edit_server_limit(group_id, node_id):
    new_limit = int(request.form.get('limit', 30))
    groups = load_auto_groups()
    if group_id not in groups or node_id not in groups[group_id]["nodes"]:
        return redirect(f'/group/{group_id}')

    ndata = groups[group_id]["nodes"][node_id]
    node_ip = str(ndata.get("ip")).strip() if isinstance(ndata, dict) else str(ndata).strip()
    
    groups[group_id]["nodes"][node_id] = {"ip": node_ip, "limit": new_limit}
    save_auto_groups(groups)

    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)

        users_on_node = [uname for uname, info in db.items() if info.get('node') == node_id]
        
        if len(users_on_node) > new_limit:
            excess_count = len(users_on_node) - new_limit
            excess_users = users_on_node[-excess_count:]

            cmds_by_ip = {}
            migrated_count = 0
            
            for uname in excess_users:
                uinfo = db[uname]
                old_port = uinfo.get('port')
                proto = uinfo.get('protocol')
                old_key_id = uinfo.get('key_id')
                
                new_node_id, new_node_ip = find_available_node(group_id, 1, current_db=db)
                if not new_node_id: break
                
                cmd_del = get_safe_delete_cmd(uname, proto, old_port)
                if node_ip not in cmds_by_ip: cmds_by_ip[node_ip] = []
                cmds_by_ip[node_ip].append(cmd_del)
                
                used_ports = [int(i.get('port', 10000)) for i in db.values() if i.get('protocol') == 'out' and i.get('node') == new_node_id]
                new_port = str(max(used_ports) + 1) if used_ports else "10001"
                
                uid = uinfo.get('uuid')
                safe_u = urllib.parse.quote(uname)

                if proto == 'v2':
                    new_port = "443"
                    k = f"vless://{uid}@{new_node_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
                    cmd_add = f"/usr/local/bin/v2ray-node-add-vless {uname} {uid}"
                else:
                    ss_conf = base64.b64encode(f"chacha20-ietf-poly1305:{uid}".encode()).decode()
                    k = f"ss://{ss_conf}@{new_node_ip}:{new_port}#{safe_u}"
                    cmd_add = f"/usr/local/bin/v2ray-node-add-out {uname} {uid} {new_port} ; ufw allow {new_port}/tcp && ufw allow {new_port}/udp"

                if new_node_ip not in cmds_by_ip: cmds_by_ip[new_node_ip] = []
                cmds_by_ip[new_node_ip].append(cmd_add)
                
                db[uname]['node'] = new_node_id
                db[uname]['port'] = new_port
                db[uname]['key'] = k
                if old_key_id: db[uname]['key_id'] = old_key_id
                migrated_count += 1
                
            with open(USERS_DB, 'w') as f: json.dump(db, f)

            for ip, cmds in cmds_by_ip.items():
                cmds.append("systemctl restart xray")
                execute_ssh_bg(ip, cmds)

    return redirect(f'/group/{group_id}')

@app.route('/add_user_auto', methods=['POST'])
def add_user_auto():
    gid = request.form.get('group_id', '')
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

    usernames = sanitize_usernames(raw_usernames)
    if not usernames: return redirect(f'/group/{gid}')

    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)

        node_id, node_ip = find_available_node(gid, len(usernames), current_db=db)
        if not node_id:
            return "<script>alert('❌ Error: Limit Reached! No space available in any server for this group.'); window.history.back();</script>"

        used_ports = [int(i.get('port', 10000)) for i in db.values() if i.get('protocol') == 'out' and i.get('node') == node_id]
        max_p = max(used_ports) if used_ports else 10000

        try: gb = float(request.form.get('total_gb') or 0)
        except: gb = 0.0
        try: days = int(request.form.get('expire_days') or 30)
        except: days = 30
        
        proto = request.form.get('protocol', 'v2')
        cmds = []
        
        existing_ids = [int(u.get('key_id', 0)) for u in db.values() if isinstance(u, dict) and str(u.get('key_id', '')).isdigit()]
        next_id = max(existing_ids) + 1 if existing_ids else 1
        
        for u in usernames:
            if u in db: continue
            uid = str(uuid.uuid4()).strip()
            
            if proto == 'v2':
                port = "443"
                safe_u = urllib.parse.quote(u)
                k = f"vless://{uid}@{node_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
                cmds.append(f"/usr/local/bin/v2ray-node-add-vless {u} {uid}")
            else:
                max_p += 1; port = str(max_p)
                ss_conf = base64.b64encode(f"chacha20-ietf-poly1305:{uid}".encode()).decode()
                k = f"ss://{ss_conf}@{node_ip}:{port}#{u}"
                cmds.append(f"/usr/local/bin/v2ray-node-add-out {u} {uid} {port} ; ufw allow {port}/tcp && ufw allow {port}/udp")
                
            exp = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
            db[u] = {"node": node_id, "group": gid, "protocol": proto, "uuid": uid, "port": port, "total_gb": gb, "expire_date": exp, "used_bytes": 0, "last_raw_bytes": 0, "is_blocked": False, "is_online": False, "key": k, "key_id": next_id}
            next_id += 1
        
        if cmds:
            with open(USERS_DB, 'w') as f: json.dump(db, f)
            cmds.append("systemctl restart xray")
            execute_ssh_bg(node_ip, cmds)
            
    return redirect(f'/group/{gid}')

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
        if not os.path.exists(NODES_LIST):
            with open(NODES_LIST, 'w') as f: f.write("")
        with open(NODES_LIST, 'a') as f: 
            f.write(f"\n{n_id}|{n_name}|{n_ip}")
    return redirect(f"/node/{n_id}?newly_added=yes")

@app.route('/delete_node/<node_id>', methods=['POST'])
def delete_node(node_id):
    nodes = get_all_servers()
    if node_id in nodes:
        node_ip = str(nodes[node_id].get('ip')).strip()
        if node_ip: execute_ssh_bg(node_ip, ["systemctl stop xray"])
    
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
        execute_ssh_bg(current_ip, commands)
    return redirect(f'/node/{old_id}')

@app.route('/api/check_ssh/<node_id>')
def check_ssh(node_id):
    ip = get_all_servers().get(node_id, {}).get('ip')
    if not ip: return jsonify({"status": "error"})
    ip = str(ip).strip()
    try:
        res = subprocess.run(f"ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@{ip} 'echo ok'", shell=True, capture_output=True, text=True)
        if "ok" in res.stdout: return jsonify({"status": "success"})
    except: pass
    return jsonify({"status": "error"})

@app.route('/api/check_xray/<node_id>')
def check_xray(node_id):
    ip = get_all_servers().get(node_id, {}).get('ip')
    if not ip: return jsonify({"status": "inactive"})
    ip = str(ip).strip()
    try:
        res = subprocess.run(f"ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@{ip} 'systemctl is-active xray'", shell=True, capture_output=True, text=True)
        if "active" in res.stdout.strip().lower(): return jsonify({"status": "active"})
    except: pass
    return jsonify({"status": "inactive"})

@app.route('/api/stats/<node_id>')
def api_stats(node_id):
    ip = get_all_servers().get(node_id, {}).get('ip')
    if not ip: return jsonify({"status": "error"})
    ip = str(ip).strip()
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
    if ip: execute_ssh_bg(str(ip).strip(), ["bash -s < /root/PanelMaster/install_node.sh"])
    return redirect(request.referrer)

@app.route('/restart_xray/<node_id>', methods=['POST'])
def restart_xray_action(node_id):
    ip = get_all_servers().get(node_id, {}).get('ip')
    if ip: execute_ssh_bg(str(ip).strip(), ["systemctl restart xray"])
    return redirect(request.referrer)

@app.route('/toggle_node/<node_id>', methods=['POST'])
def toggle_node(node_id):
    config = load_config()
    if 'disabled_nodes' not in config: config['disabled_nodes'] = []
    ip = get_all_servers().get(node_id, {}).get('ip')
    if node_id in config['disabled_nodes']:
        config['disabled_nodes'].remove(node_id)
        if ip: execute_ssh_bg(str(ip).strip(), ["systemctl start xray"])
    else:
        config['disabled_nodes'].append(node_id)
        if ip: execute_ssh_bg(str(ip).strip(), ["systemctl stop xray"])
    save_config(config); return redirect(request.referrer)

@app.route('/add_user_manual', methods=['POST'])
def add_user_manual():
    nid = request.form.get('node_id'); nip = get_all_servers().get(nid, {}).get('ip')
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
        base = request.form.get('base_name', '').strip(); start = int(request.form.get('start_num', 1)); qty = int(request.form.get('qty', 1))
        raw_usernames = [f"{base}{start+i}" for i in range(qty)]

    usernames = sanitize_usernames(raw_usernames)
    if not usernames: return redirect(f'/node/{nid}')

    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            
        used_ports = [int(i.get('port', 10000)) for i in db.values() if i.get('protocol') == 'out' and i.get('node') == nid]
        max_p = max(used_ports) if used_ports else 10000

        try: gb = float(request.form.get('total_gb') or 0)
        except: gb = 0.0
        try: days = int(request.form.get('expire_days') or 30)
        except: days = 30
        
        proto = request.form.get('protocol', 'v2')
        cmds = []
        
        existing_ids = [int(u.get('key_id', 0)) for u in db.values() if isinstance(u, dict) and str(u.get('key_id', '')).isdigit()]
        next_id = max(existing_ids) + 1 if existing_ids else 1
        
        for u in usernames:
            if u in db: continue
            uid = str(uuid.uuid4()).strip()
            
            if proto == 'v2':
                port = "443"
                safe_u = urllib.parse.quote(u)
                k = f"vless://{uid}@{nip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
                cmds.append(f"/usr/local/bin/v2ray-node-add-vless {u} {uid}")
            else:
                max_p += 1; port = str(max_p)
                ss_conf = base64.b64encode(f"chacha20-ietf-poly1305:{uid}".encode()).decode()
                k = f"ss://{ss_conf}@{nip}:{port}#{u}"
                cmds.append(f"/usr/local/bin/v2ray-node-add-out {u} {uid} {port} ; ufw allow {port}/tcp && ufw allow {port}/udp")
                
            exp = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
            db[u] = {"node": nid, "group": gid, "protocol": proto, "uuid": uid, "port": port, "total_gb": gb, "expire_date": exp, "used_bytes": 0, "last_raw_bytes": 0, "is_blocked": False, "is_online": False, "key": k, "key_id": next_id}
            next_id += 1
        
        if cmds:
            with open(USERS_DB, 'w') as f: json.dump(db, f)
            cmds.append("systemctl restart xray")
            execute_ssh_bg(nip, cmds)
            
    return redirect(request.referrer)

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
                    execute_ssh_bg(ip, [cmd, "systemctl restart xray"])
                with open(USERS_DB, 'w') as f: json.dump(db, f)
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
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                info = db[username]; ip = get_all_servers().get(info.get('node'), {}).get('ip')
                if ip:
                    cmd = get_safe_delete_cmd(username, info.get('protocol', 'v2'), info.get('port', '443'))
                    execute_ssh_bg(ip, [cmd, "systemctl restart xray"])
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
            cmds_by_ip = {}
            for uname in usernames:
                if uname in db:
                    ip = nodes.get(db[uname].get('node'), {}).get('ip')
                    if ip:
                        cmd = get_safe_delete_cmd(uname, db[uname].get('protocol', 'v2'), db[uname].get('port', '443'))
                        cmds_by_ip.setdefault(ip, []).append(cmd)
                    del db[uname]
            with open(USERS_DB, 'w') as f: json.dump(db, f)
            for ip, cmds in cmds_by_ip.items():
                cmds.append("systemctl restart xray")
                execute_ssh_bg(ip, cmds)
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
