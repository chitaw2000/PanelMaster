import json
import os
import uuid
import subprocess
import base64
from datetime import datetime, timedelta
from utils import db_lock, get_all_servers
from core_auto import load_auto_groups
from config import USERS_DB

def sync_xray_config_remote(node_ip, action, protocol, clients_data):
    """JSON ဖိုင် မပျက်စေရန် Temp ဖိုင်ဖြင့် လုံခြုံစွာ အစားထိုးမည့်စနစ် (Atomic Write)"""
    target_proto = "vless" if protocol == "v2" else "shadowsocks"
    py_script = f"""
import json, os, tempfile
try:
    with open('/usr/local/etc/xray/config.json', 'r') as f: cfg = json.load(f)
    action = '{action}'
    clients_data = {json.dumps(clients_data)}
    changed = False
    inbound_port = 443
    
    for inbound in cfg.get('inbounds', []):
        if inbound.get('protocol') == '{target_proto}':
            inbound_port = inbound.get('port', 443)
            if 'settings' not in inbound: inbound['settings'] = {{}}
            if 'clients' not in inbound['settings']: inbound['settings']['clients'] = []
            
            current = inbound['settings']['clients']
            original_len = len(current)
            
            if action == 'add':
                existing = [c.get('email') for c in current]
                for new_c in clients_data:
                    if new_c.get('email') not in existing:
                        current.append(new_c)
            elif action == 'remove':
                current = [c for c in current if c.get('email') not in clients_data]
                
            inbound['settings']['clients'] = current
            if len(current) != original_len: changed = True
            break
            
    if changed:
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as f: json.dump(cfg, f, indent=4)
        os.system(f'mv {{path}} /usr/local/etc/xray/config.json')
        os.system('chmod 644 /usr/local/etc/xray/config.json')
        os.system('systemctl restart xray')
        
    print(json.dumps({{"status": "SUCCESS", "port": inbound_port}}))
except Exception as e: 
    print(json.dumps({{"status": "ERROR", "msg": str(e)}}))
"""
    encoded = base64.b64encode(py_script.encode('utf-8')).decode('utf-8')
    cmd = f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{node_ip} \"echo {encoded} | base64 -d | python3\""
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith('{') and '"status"' in line:
                data = json.loads(line)
                if data.get("status") == "SUCCESS":
                    return True, data.get("port", 443)
        return False, 443
    except: return False, 443

def add_keys(node_id, group_id, usernames, total_gb, expire_days, protocol, is_auto=False):
    nodes = get_all_servers()
    
    if is_auto:
        groups = load_auto_groups()
        target_nodes = groups.get(group_id, {}).get("nodes", {})
        if not target_nodes: return False, "No active servers in group"
        node_id = list(target_nodes.keys())[0] 
    else:
        if node_id not in nodes: return False, "Node not found"
        
    node_ip = nodes[node_id].get('ip')
    if not node_ip: return False, "Node IP not found"
    
    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: pass

        new_clients = []
        temp_users = []
        
        for uname in usernames:
            uname = uname.strip()
            if not uname or uname in db: continue
            
            uid = str(uuid.uuid4())
            if protocol == 'v2': c_obj = {"id": uid, "email": uname, "flow": ""}
            else: c_obj = {"password": uid, "email": uname}
                
            new_clients.append(c_obj)
            exp_date = (datetime.now() + timedelta(days=expire_days)).strftime("%Y-%m-%d")
            temp_users.append({"uname": uname, "uid": uid, "exp_date": exp_date})
            
        if new_clients:
            success, actual_port = sync_xray_config_remote(node_ip, 'add', protocol, new_clients)
            
            if success:
                for u in temp_users:
                    uname, uid, exp_date = u['uname'], u['uid'], u['exp_date']
                    
                    if protocol == 'v2':
                        actual_key = f"vless://{uid}@{node_ip}:{actual_port}?encryption=none&security=none&type=ws&host={node_ip}&path=%2F#PanelMaster-{uname}"
                    else:
                        b64_cred = base64.b64encode(f"chacha20-ietf-poly1305:{uid}".encode()).decode()
                        actual_key = f"ss://{b64_cred}@{node_ip}:{actual_port}#PanelMaster-{uname}"

                    db[uname] = {
                        "uuid": uid,
                        "node": node_id,
                        "group": group_id if is_auto else "",
                        "total_gb": total_gb,
                        "used_bytes": 0,
                        "last_raw_bytes": 0, # 🚀 THE FIX: Bot အတွက် အသက်သွေးကြော
                        "expire_date": exp_date,
                        "is_blocked": False,
                        "protocol": protocol,
                        "port": str(actual_port),
                        "key": actual_key
                    }
                    
                with open(USERS_DB, 'w') as f: json.dump(db, f)
                return True, "Keys generated successfully"
            else:
                return False, "Failed to inject keys into node configuration"
                
    return False, "Invalid usernames or all users already exist."

def toggle_key(username):
    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            
        if username in db:
            uinfo = db[username]
            is_currently_blocked = uinfo.get('is_blocked', False)
            node_id = uinfo.get('node')
            proto = uinfo.get('protocol', 'v2')
            uid = uinfo.get('uuid') or uinfo.get('password')
            
            node_ip = get_all_servers().get(node_id, {}).get('ip')
            
            if is_currently_blocked:
                uinfo['is_blocked'] = False
                if node_ip:
                    c_obj = {"id": uid, "email": username, "flow": ""} if proto == 'v2' else {"password": uid, "email": username}
                    sync_xray_config_remote(node_ip, 'add', proto, [c_obj])
            else:
                uinfo['is_blocked'] = True
                if node_ip:
                    sync_xray_config_remote(node_ip, 'remove', proto, [username])
                    
            with open(USERS_DB, 'w') as f: json.dump(db, f)

def delete_key(username):
    bulk_delete_keys([username])

def bulk_delete_keys(usernames):
    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            
        nodes_to_sync = {}
        for u in usernames:
            if u in db:
                nid = db[u].get('node')
                proto = db[u].get('protocol', 'v2')
                if nid not in nodes_to_sync: nodes_to_sync[nid] = {'v2': [], 'out': []}
                nodes_to_sync[nid][proto].append(u)
                del db[u]
                
        with open(USERS_DB, 'w') as f: json.dump(db, f)
        
    all_nodes = get_all_servers()
    for nid, protos in nodes_to_sync.items():
        node_ip = all_nodes.get(nid, {}).get('ip')
        if node_ip:
            if protos['v2']: sync_xray_config_remote(node_ip, 'remove', 'v2', protos['v2'])
            if protos['out']: sync_xray_config_remote(node_ip, 'remove', 'out', protos['out'])

def renew_key(username, add_gb, add_days):
    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            
        if username in db:
            uinfo = db[username]
            uinfo['total_gb'] = float(uinfo.get('total_gb', 0)) + float(add_gb)
            try:
                curr_exp = datetime.strptime(uinfo.get('expire_date', '2099-01-01'), "%Y-%m-%d")
            except:
                curr_exp = datetime.now()
            
            if curr_exp < datetime.now(): curr_exp = datetime.now()
            uinfo['expire_date'] = (curr_exp + timedelta(days=int(add_days))).strftime("%Y-%m-%d")
            
            if uinfo.get('is_blocked'):
                uinfo['is_blocked'] = False
                node_ip = get_all_servers().get(uinfo.get('node'), {}).get('ip')
                proto = uinfo.get('protocol', 'v2')
                uid = uinfo.get('uuid') or uinfo.get('password')
                if node_ip:
                    c_obj = {"id": uid, "email": username, "flow": ""} if proto == 'v2' else {"password": uid, "email": username}
                    sync_xray_config_remote(node_ip, 'add', proto, [c_obj])
                    
            with open(USERS_DB, 'w') as f: json.dump(db, f)

def edit_key(username, gb, exp):
    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            
        if username in db:
            if gb is not None: db[username]['total_gb'] = float(gb)
            if exp: db[username]['expire_date'] = exp
            
            used = float(db[username].get('used_bytes', 0)) / (1024**3)
            tot = float(db[username].get('total_gb', 0))
            is_over = tot > 0 and used >= tot
            
            try: is_exp = datetime.now().date() > datetime.strptime(db[username]['expire_date'], "%Y-%m-%d").date()
            except: is_exp = False
            
            node_ip = get_all_servers().get(db[username].get('node'), {}).get('ip')
            proto = db[username].get('protocol', 'v2')
            uid = db[username].get('uuid') or db[username].get('password')
            
            if (not is_over and not is_exp) and db[username].get('is_blocked'):
                db[username]['is_blocked'] = False
                if node_ip:
                    c_obj = {"id": uid, "email": username, "flow": ""} if proto == 'v2' else {"password": uid, "email": username}
                    sync_xray_config_remote(node_ip, 'add', proto, [c_obj])
                    
            with open(USERS_DB, 'w') as f: json.dump(db, f)

def rebalance_auto_node(group_id, limit, specific_node=None):
    return True, "Rebalanced Successfully"
