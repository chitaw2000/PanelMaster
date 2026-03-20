from flask import Flask, render_template, request, redirect, session, url_for, send_file, jsonify
import json, os, re, subprocess, urllib.parse
from datetime import datetime, timedelta

from config import SECRET_KEY, USERS_DB, NODES_LIST, CONFIG_FILE, ADMIN_PASS, load_config, save_config
from utils import get_nodes, get_all_servers, check_live_status, db_lock, AUTO_GROUPS_FILE, NODES_DB
from core_auto import load_auto_groups, save_auto_groups

from core_engine import execute_ssh_bg, get_safe_delete_cmd
from core_monitor import start_background_monitor
from core_node import add_keys, toggle_key, delete_key, bulk_delete_keys, renew_key, edit_key, rebalance_auto_node
from core_ip import get_active_ips

app = Flask(__name__)
app.secret_key = SECRET_KEY
BACKUP_DIR = "/root/PanelMaster/backups"

if not os.path.exists(BACKUP_DIR): 
    os.makedirs(BACKUP_DIR)

start_background_monitor()

@app.before_request
def check_auth():
    if request.endpoint not in ['login', 'static', 'api_stats', 'api_user_ip'] and not session.get('logged_in'): 
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASS:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout(): 
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/user_ip/<username>')
def api_user_ip(username):
    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
    
    if username not in db: return jsonify({"status": "error", "msg": "User not found"})
    
    uinfo = db[username]
    node_id = uinfo.get('node')
    port = uinfo.get('port', '443')
    proto = uinfo.get('protocol', 'v2')
    
    nodes = get_all_servers()
    node_ip = nodes.get(node_id, {}).get('ip')
    
    if not node_ip: return jsonify({"status": "error", "msg": "Node offline"})
    
    ips_info = get_active_ips(node_ip, port, proto, username)
    return jsonify({"status": "success", "data": ips_info})

@app.route('/fix_node_logs/<node_id>', methods=['POST'])
def fix_node_logs(node_id):
    nodes = get_all_servers()
    ip = nodes.get(node_id, {}).get('ip')
    if ip:
        cmds = [
            "mkdir -p /var/log/xray",
            "touch /var/log/xray/access.log",
            "chmod 777 /var/log/xray/access.log",
            "grep -q 'access.log' /usr/local/etc/xray/config.json || sed -i 's/\"log\": {/\"log\": {\\n    \"access\": \"\\/var\\/log\\/xray\\/access.log\",/g' /usr/local/etc/xray/config.json",
            "systemctl restart xray"
        ]
        execute_ssh_bg(str(ip).strip(), cmds)
    return redirect(request.referrer)

@app.route('/set_node_health/<node_id>', methods=['POST'])
def set_node_health(node_id):
    health = request.form.get('health', 'green')
    with db_lock:
        ndb = {}
        if os.path.exists(NODES_DB):
            try:
                with open(NODES_DB, 'r') as f: ndb = json.load(f)
            except: pass
        if node_id not in ndb: ndb[node_id] = {"used_bytes": 0, "limit_tb": 0, "health": "green"}
        ndb[node_id]["health"] = health
        with open(NODES_DB, 'w') as f: json.dump(ndb, f)
    return redirect(request.referrer)

@app.route('/set_node_traffic/<node_id>', methods=['POST'])
def set_node_traffic(node_id):
    try: tb = float(request.form.get('limit_tb', 0))
    except: tb = 0.0
    with db_lock:
        ndb = {}
        if os.path.exists(NODES_DB):
            try:
                with open(NODES_DB, 'r') as f: ndb = json.load(f)
            except: pass
        if node_id not in ndb: ndb[node_id] = {"used_bytes": 0, "limit_tb": 0, "health": "green"}
        ndb[node_id]["limit_tb"] = tb
        with open(NODES_DB, 'w') as f: json.dump(ndb, f)
    return redirect(request.referrer)

@app.route('/reset_node_traffic/<node_id>', methods=['POST'])
def reset_node_traffic(node_id):
    with db_lock:
        ndb = {}
        if os.path.exists(NODES_DB):
            try:
                with open(NODES_DB, 'r') as f: ndb = json.load(f)
            except: pass
        if node_id in ndb:
            ndb[node_id]["used_bytes"] = 0
            with open(NODES_DB, 'w') as f: json.dump(ndb, f)
    return redirect(request.referrer)

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
                    ctime = datetime.fromtimestamp(os.path.getctime(path)).strftime('%Y-%m-%d %I:%M %p')
                    backups[nid].append({"filename": f, "size": f"{size:.1f} KB", "time": ctime})
    return backups

@app.route('/')
def dashboard():
    nodes = get_nodes()
    auto_groups = load_auto_groups()
    db = {}
    ndb = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: pass
        if os.path.exists(NODES_DB):
            try:
                with open(NODES_DB, 'r') as f: ndb = json.load(f)
            except: pass
                
    config = load_config()
    active_users = check_live_status(db)
    node_stats = []
    group_stats = []
    
    node_used_bytes = {}
    group_used_bytes = {}
    
    for uname, uinfo in db.items():
        nid = uinfo.get('node')
        gid = uinfo.get('group')
        if nid: node_used_bytes[nid] = node_used_bytes.get(nid, 0) + float(uinfo.get('used_bytes', 0))
        if gid: group_used_bytes[gid] = group_used_bytes.get(gid, 0) + float(uinfo.get('used_bytes', 0))
    
    all_servers = get_all_servers()
    sick_nodes = {'blue': [], 'yellow': [], 'orange': [], 'red': []}
    sick_count = 0
    for nid, info in all_servers.items():
        h = ndb.get(nid, {}).get("health", "green")
        if h in sick_nodes:
            sick_nodes[h].append({"id": nid, "name": info.get('name', nid), "ip": info.get('ip', '')})
            sick_count += 1
            
    for nid, info in nodes.items():
        total_count = sum(1 for i in db.values() if i.get('node') == nid and not i.get('group'))
        live_count = sum(1 for uname, i in db.items() if i.get('node') == nid and not i.get('group') and uname in active_users and not i.get('is_blocked'))
        
        ninfo = ndb.get(nid, {})
        limit_tb = float(ninfo.get("limit_tb", 0))
        used_gb = node_used_bytes.get(nid, 0) / (1024**3)
        limit_gb = limit_tb * 1024
        is_alarm = limit_gb > 0 and used_gb >= limit_gb
        health = ninfo.get("health", "green")

        node_stats.append({
            "id": nid, "name": info.get('name', nid), "ip": info.get('ip', ''), 
            "total": total_count, "live": live_count, "disabled": nid in config.get('disabled_nodes', []),
            "used_gb": used_gb, "limit_tb": limit_tb, "is_alarm": is_alarm, "health": health
        })
        
    for gid, gdata in auto_groups.items():
        limit = gdata.get("limit", 30)
        g_nodes = gdata.get("nodes", {})
        g_keys = sum(1 for i in db.values() if i.get("group") == gid)
        g_used_gb = group_used_bytes.get(gid, 0) / (1024**3)
        group_stats.append({"id": gid, "name": gdata.get("name", gid), "limit": limit, "node_count": len(g_nodes), "total_keys": g_keys, "used_gb": g_used_gb})

    # 🚀 THE FIX: Backup များကို Custom နှင့် Auto ခွဲခြားခြင်း
    raw_backups = get_node_backups()
    custom_backups = {}
    auto_backups = {}
    orphaned_backups = {}
    
    auto_nids_map = {}
    for gid, gdata in auto_groups.items():
        auto_backups[gid] = {"name": gdata.get('name', gid), "nodes": {}}
        for nid in gdata.get('nodes', {}).keys():
            auto_nids_map[nid] = gid
            
    for nid, files in raw_backups.items():
        if nid in nodes:
            custom_backups[nid] = {"name": nodes[nid].get('name', nid), "files": files}
        elif nid in auto_nids_map:
            gid = auto_nids_map[nid]
            auto_backups[gid]["nodes"][nid] = files
        else:
            orphaned_backups[nid] = files
            
    # အလွတ်ဖြစ်နေသော Auto Group များကို ဖယ်ရှားမည်
    auto_backups = {k: v for k, v in auto_backups.items() if v["nodes"]}

    return render_template('dashboard.html', nodes=node_stats, groups=group_stats, config=config, custom_backups=custom_backups, auto_backups=auto_backups, orphaned_backups=orphaned_backups, sick_nodes=sick_nodes, sick_count=sick_count)

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
    if group_id not in groups: 
        return redirect(url_for('dashboard'))
        
    group = groups[group_id]
    db = {}
    ndb = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
        if os.path.exists(NODES_DB):
            try:
                with open(NODES_DB, 'r') as f: ndb = json.load(f)
            except: pass
            
    active_users = check_live_status(db)
    users = []
    server_stats = []
    g_nodes = group.get("nodes", {})
    counts = {nid: 0 for nid in g_nodes.keys()}
    
    node_used_bytes = {}
    group_total_bytes = 0
    
    for uname, info in db.items():
        if info.get('group') == group_id:
            info['used_bytes'] = float(info.get('used_bytes', 0))
            info['total_gb'] = float(info.get('total_gb', 0))
            info['used_gb_str'] = f"{(info['used_bytes'] / (1024**3)):.2f}"
            info['username'] = uname
            info['actual_key'] = info.get('key') or "No Key Found"
            info['is_active'] = uname in active_users and not info.get('is_blocked')
            users.append(info)
            
            nid = info.get('node')
            if nid in counts: counts[nid] += 1
            if nid: node_used_bytes[nid] = node_used_bytes.get(nid, 0) + info['used_bytes']
            group_total_bytes += info['used_bytes']
            
    users = sorted(users, key=lambda x: int(x.get('key_id', 0)))
    group_used_gb = group_total_bytes / (1024**3)
            
    for nid, ndata in g_nodes.items():
        if isinstance(ndata, dict):
            nip = str(ndata.get("ip")).strip()
            limit = int(ndata.get("limit", group.get("limit", 30)))
        else:
            nip = str(ndata).strip()
            limit = int(group.get("limit", 30))
            
        ninfo = ndb.get(nid, {})
        limit_tb = float(ninfo.get("limit_tb", 0))
        used_gb = node_used_bytes.get(nid, 0) / (1024**3)
        limit_gb = limit_tb * 1024
        is_alarm = limit_gb > 0 and used_gb >= limit_gb
        health = ninfo.get("health", "green")
        
        server_stats.append({"id": nid, "ip": nip, "count": counts[nid], "limit": limit, "used_gb": used_gb, "limit_tb": limit_tb, "is_alarm": is_alarm, "health": health})
        
    return render_template('group.html', group_id=group_id, group=group, users=users, server_stats=server_stats, group_used_gb=group_used_gb)

@app.route('/add_server_to_group/<group_id>', methods=['POST'])
def add_server_to_group(group_id):
    nid = request.form.get('node_id', '').strip().replace(" ", "_")
    nip = request.form.get('node_ip', '').strip()
    limit = int(request.form.get('limit', 30))
    groups = load_auto_groups()
    nodes = get_all_servers()
    
    if nid in nodes:
        return f"<script>alert('Error: Server ID [{nid}] already exists!'); window.history.back();</script>"
        
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
                with open(USERS_DB, 'r') as f: 
                    db = json.load(f)
                users_to_delete = [u for u, info in db.items() if info.get('node') == node_id]
        if users_to_delete: 
            bulk_delete_keys(users_to_delete)
            
    return redirect(f'/group/{group_id}')

@app.route('/edit_group_limit/<group_id>', methods=['POST'])
def edit_group_limit(group_id):
    new_limit = int(request.form.get('limit', 30))
    success, msg = rebalance_auto_node(group_id, new_limit)
    if not success: 
        return f"<script>alert('{msg}'); window.location.href='/group/{group_id}';</script>"
    return redirect(f'/group/{group_id}')

@app.route('/edit_server_limit/<group_id>/<node_id>', methods=['POST'])
def edit_server_limit(group_id, node_id):
    new_limit = int(request.form.get('limit', 30))
    success, msg = rebalance_auto_node(group_id, new_limit, specific_node=node_id)
    if not success: 
        return f"<script>alert('{msg}'); window.location.href='/group/{group_id}';</script>"
    return redirect(f'/group/{group_id}')

@app.route('/add_user_auto', methods=['POST'])
def add_user_auto():
    gid = request.form.get('group_id', '').strip()
    mode = request.form.get('creation_mode', 'single')
    
    raw_usernames = []
    if mode == 'single': 
        raw_usernames = [request.form.get('single_username', '')]
    elif mode == 'list': 
        raw_usernames = re.split(r'[,\n\r]+', request.form.get('list_usernames', ''))
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

    success, msg = add_keys(None, gid, raw_usernames, gb, days, proto, is_auto=True)
    if not success: 
        return f"<script>alert('{msg}'); window.history.back();</script>"
    return redirect(f'/group/{gid}')

@app.route('/node/<node_id>')
def node_view(node_id):
    nodes = get_all_servers()
    if node_id not in nodes: 
        return redirect(url_for('dashboard'))
        
    node_info = nodes[node_id]
    db = {}
    ndb = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: pass
        if os.path.exists(NODES_DB):
            try:
                with open(NODES_DB, 'r') as f: ndb = json.load(f)
            except: pass
            
    config = load_config()
    active_users = check_live_status(db)
    users = []
    node_used_bytes = 0
    for uname, info in db.items():
        if info.get('node') == node_id:
            info['used_bytes'] = float(info.get('used_bytes', 0))
            info['total_gb'] = float(info.get('total_gb', 0))
            info['used_gb_str'] = f"{(info['used_bytes'] / (1024**3)):.2f}"
            info['username'] = uname
            info['actual_key'] = info.get('key') or "No Key Found"
            info['is_active'] = uname in active_users and not info.get('is_blocked')
            users.append(info)
            node_used_bytes += info['used_bytes']
            
    ninfo = ndb.get(node_id, {})
    limit_tb = float(ninfo.get("limit_tb", 0))
    used_gb = node_used_bytes / (1024**3)
    limit_gb = limit_tb * 1024
    is_alarm = limit_tb > 0 and used_gb >= limit_gb
    health = ninfo.get("health", "green")
            
    other_nodes = [nid for nid in nodes.keys() if nid != node_id]
    return render_template('node.html', node_id=node_id, node_name=node_info.get('name', ''), node_ip=node_info.get('ip', ''), users=users, other_nodes=other_nodes, config=config, used_gb=used_gb, limit_tb=limit_tb, is_alarm=is_alarm, health=health)

@app.route('/add_node', methods=['POST'])
def add_node():
    n_id = request.form.get('node_id', '').strip().replace(" ", "_")
    n_name = request.form.get('node_name', '').strip()
    n_ip = request.form.get('node_ip', '').strip()
    
    if n_id and n_name and n_ip:
        nodes = get_all_servers()
        if n_id in nodes:
            return f"<script>alert('Error: Node ID [{n_id}] already exists!'); window.history.back();</script>"
            
        if not os.path.exists(NODES_LIST):
            with open(NODES_LIST, 'w') as f: 
                f.write("")
        with open(NODES_LIST, 'a') as f: 
            f.write(f"\n{n_id}|{n_name}|{n_ip}")
    return redirect(f"/node/{n_id}?newly_added=yes")

@app.route('/delete_node/<node_id>', methods=['POST'])
def delete_node(node_id):
    nodes = get_all_servers()
    if node_id in nodes:
        node_ip = str(nodes[node_id].get('ip')).strip()
        if node_ip: 
            execute_ssh_bg(node_ip, ["systemctl stop xray"])
    
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f: 
            lines = f.readlines()
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
    if node_id in config.get('disabled_nodes', []): 
        config['disabled_nodes'].remove(node_id)
        save_config(config)
        
    if is_auto: 
        return redirect(request.referrer)
    return redirect(url_for('dashboard'))

@app.route('/replace_id/<current_id>', methods=['POST'])
def replace_id(current_id):
    old_id = request.form.get('old_id', '').strip()
    nodes = get_all_servers()
    if current_id not in nodes or not old_id: 
        return redirect(f'/node/{current_id}')
    
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f: 
            lines = f.readlines()
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
                    else: 
                        f.write(line)
                    
    groups = load_auto_groups()
    for gid, gdata in groups.items():
        if current_id in gdata.get("nodes", {}):
            ndata = gdata["nodes"][current_id]
            del groups[gid]["nodes"][current_id]
            groups[gid]["nodes"][old_id] = ndata
            save_auto_groups(groups)
            break
            
    return redirect(f'/node/{old_id}')

@app.route('/api/check_ssh/<node_id>')
def check_ssh(node_id):
    ip = get_all_servers().get(node_id, {}).get('ip')
    if not ip: 
        return jsonify({"status": "error"})
    ip = str(ip).strip()
    try:
        res = subprocess.run(f"ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@{ip} 'echo ok'", shell=True, capture_output=True, text=True)
        if "ok" in res.stdout: 
            return jsonify({"status": "success"})
    except: 
        pass
    return jsonify({"status": "error"})

@app.route('/api/check_xray/<node_id>')
def check_xray(node_id):
    ip = get_all_servers().get(node_id, {}).get('ip')
    if not ip: 
        return jsonify({"status": "inactive"})
    ip = str(ip).strip()
    try:
        res = subprocess.run(f"ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@{ip} 'systemctl is-active xray'", shell=True, capture_output=True, text=True)
        if "active" in res.stdout.strip().lower(): 
            return jsonify({"status": "active"})
    except: 
        pass
    return jsonify({"status": "inactive"})

@app.route('/api/stats/<node_id>')
def api_stats(node_id):
    ip = get_all_servers().get(node_id, {}).get('ip')
    if not ip: 
        return jsonify({"status": "error"})
    ip = str(ip).strip()
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
    ip = get_all_servers().get(node_id, {}).get('ip')
    if ip: 
        execute_ssh_bg(str(ip).strip(), ["bash -s < /root/PanelMaster/install_node.sh"])
    return redirect(request.referrer)

@app.route('/restart_xray/<node_id>', methods=['POST'])
def restart_xray_action(node_id):
    ip = get_all_servers().get(node_id, {}).get('ip')
    if ip: 
        execute_ssh_bg(str(ip).strip(), ["systemctl restart xray"])
    return redirect(request.referrer)

@app.route('/toggle_node/<node_id>', methods=['POST'])
def toggle_node(node_id):
    config = load_config()
    if 'disabled_nodes' not in config: 
        config['disabled_nodes'] = []
    ip = get_all_servers().get(node_id, {}).get('ip')
    
    if node_id in config['disabled_nodes']:
        config['disabled_nodes'].remove(node_id)
        if ip: execute_ssh_bg(str(ip).strip(), ["systemctl start xray"])
    else:
        config['disabled_nodes'].append(node_id)
        if ip: execute_ssh_bg(str(ip).strip(), ["systemctl stop xray"])
        
    save_config(config)
    return redirect(request.referrer)

@app.route('/add_user_manual', methods=['POST'])
def add_user_manual():
    nid = request.form.get('node_id')
    nip = get_all_servers().get(nid, {}).get('ip')
    if not nip: 
        return redirect(f'/node/{nid}')
    
    gid = ""
    groups = load_auto_groups()
    for g_id, gdata in groups.items():
        if nid in gdata.get("nodes", {}): 
            gid = g_id
            break

    mode = request.form.get('creation_mode', 'single')
    raw_usernames = []
    if mode == 'single': 
        raw_usernames = [request.form.get('single_username', '')]
    elif mode == 'list': 
        raw_usernames = re.split(r'[,\n\r]+', request.form.get('list_usernames', ''))
    elif mode == 'pattern':
        base = request.form.get('base_name', '').strip()
        try: start = int(request.form.get('start_num', 1))
        except: start = 1
        try: qty = int(request.form.get('qty', 1))
        except: qty = 1
        raw_usernames = [f"{base}{start+i}" for i in range(qty)]

    try: gb = float(request.form.get('total_gb') or 0)
    except: gb = 0.0
    try: days = int(request.form.get('expire_days') or 30)
    except: days = 30
    
    proto = request.form.get('protocol', 'v2')
    
    success, msg = add_keys(nid, gid, raw_usernames, gb, days, proto, is_auto=False)
    if not success: 
        return f"<script>alert('{msg}'); window.history.back();</script>"
        
    return redirect(request.referrer)

@app.route('/toggle_user/<username>', methods=['POST'])
def toggle_user(username):
    toggle_key(username)
    return redirect(request.referrer)

@app.route('/edit_user/<username>', methods=['POST'])
def edit_user_route(username):
    try: gb = float(request.form.get('total_gb') or 0)
    except: gb = None
    exp = request.form.get('expire_date', '')
    new_uuid = request.form.get('uuid', '').strip()
    
    edit_key(username, gb, exp)
    
    if new_uuid:
        with db_lock:
            db = {}
            if os.path.exists(USERS_DB):
                with open(USERS_DB, 'r') as f: db = json.load(f)
                
            if username in db:
                uinfo = db[username]
                old_uuid = uinfo.get('uuid') or uinfo.get('password')
                
                if old_uuid and old_uuid != new_uuid:
                    if 'uuid' in uinfo: uinfo['uuid'] = new_uuid
                    elif 'password' in uinfo: uinfo['password'] = new_uuid
                    if 'key' in uinfo and old_uuid in uinfo['key']:
                        uinfo['key'] = uinfo['key'].replace(old_uuid, new_uuid)
                    with open(USERS_DB, 'w') as f: json.dump(db, f)
                    
                    node_id = uinfo.get('node')
                    nodes = get_all_servers()
                    node_ip = nodes.get(node_id, {}).get('ip')
                    if node_ip:
                        cmd = f"sed -i 's/{old_uuid}/{new_uuid}/g' /usr/local/etc/xray/config.json && systemctl restart xray"
                        execute_ssh_bg(str(node_ip).strip(), [cmd])

    return redirect(request.referrer)

@app.route('/renew_user/<username>', methods=['POST'])
def renew_user_route(username):
    try: add_gb = float(request.form.get('add_gb') or 50)
    except: add_gb = 50.0
    try: add_days = int(request.form.get('add_days') or 30)
    except: add_days = 30
    renew_key(username, add_gb, add_days)
    return redirect(request.referrer)

@app.route('/delete_user/<username>', methods=['POST'])
def delete_user_route(username):
    delete_key(username)
    return redirect(request.referrer)

@app.route('/bulk_delete', methods=['POST'])
def bulk_delete_route():
    usernames = request.form.getlist('usernames')
    bulk_delete_keys(usernames)
    return redirect(request.referrer)

@app.route('/create_node_backup/<node_id>', methods=['POST'])
def create_node_backup(node_id):
    if os.path.exists(USERS_DB):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"backup_{node_id}_{timestamp}.json"
        node_data = {}
        with db_lock:
            with open(USERS_DB, 'r') as f: 
                db = json.load(f)
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

@app.route('/delete_backup/<filename>', methods=['POST'])
def delete_backup(filename):
    path = os.path.join(BACKUP_DIR, filename)
    if os.path.exists(path): 
        os.remove(path)
    return redirect(request.referrer)

@app.route('/purge_node/<node_id>', methods=['POST'])
def purge_node(node_id):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: 
                db = json.load(f)
            users_to_delete = [u for u, info in db.items() if info.get('node') == node_id]
            for u in users_to_delete: 
                del db[u]
            with open(USERS_DB, 'w') as f: 
                json.dump(db, f)
                
    if os.path.exists(BACKUP_DIR):
        for f in os.listdir(BACKUP_DIR):
            if f.startswith(f"backup_{node_id}_"): 
                os.remove(os.path.join(BACKUP_DIR, f))
    return redirect(request.referrer)

@app.route('/download_backup_global')
def download_backup_global():
    if os.path.exists(USERS_DB): 
        return send_file(USERS_DB, as_attachment=True, download_name=f"qito_db_backup.json")
    return "No DB found."

@app.route('/upload_backup', methods=['POST'])
def upload_backup():
    file = request.files.get('backup_file')
    if file: 
        file.save(USERS_DB)
    return redirect(url_for('dashboard'))

@app.route('/save_settings_basic', methods=['POST'])
def save_settings_basic():
    config = load_config()
    try: config['interval'] = int(request.form.get('interval', 12))
    except: config['interval'] = 12
    config['bot_token'] = request.form.get('bot_token', '')
    save_config(config)
    return redirect(url_for('dashboard'))

@app.route('/config_action', methods=['POST'])
def config_action():
    config = load_config()
    ctype = request.form.get('type')
    action = request.form.get('action')
    val = request.form.get('val', '').strip()
    target_list = 'admin_ids' if ctype == 'admin' else 'mod_ids'
    
    if action == 'add' and val:
        if val not in config.get(target_list, []):
            config.setdefault(target_list, []).append(val)
    elif action == 'del' and val:
        if val in config.get(target_list, []):
            config[target_list].remove(val)
            
    save_config(config)
    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)
