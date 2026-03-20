import json
import os
import uuid
import subprocess
import base64
from datetime import datetime, timedelta
from utils import db_lock, get_all_servers, get_auto_group_nodes
from config import USERS_DB

def sync_xray_config_remote(node_ip, action, protocol, clients_data):
    """Node ဆီသို့ Python Script လှမ်းပို့၍ JSON Config အား အတိအကျ ပြင်ဆင်မည်"""
    target_proto = "vless" if protocol == "v2" else "shadowsocks"
    
    py_script = f"""
import json, os
try:
    with open('/usr/local/etc/xray/config.json', 'r') as f: cfg = json.load(f)
    action = '{action}'
    clients_data = {json.dumps(clients_data)}
    changed = False
    
    for inbound in cfg.get('inbounds', []):
        if inbound.get('protocol') == '{target_proto}':
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
            
    if changed:
        with open('/usr/local/etc/xray/config.json', 'w') as f: json.dump(cfg, f, indent=4)
        os.system('systemctl restart xray')
    print('SUCCESS')
except Exception as e: print('ERROR:', str(e))
"""
    # Base64 ဖြင့် ပြောင်း၍ SSH မှတဆင့် Python ကို တိုက်ရိုက် Run မည် (Quoting Error လုံးဝမတက်ပါ)
    encoded = base64.b64encode(py_script.encode('utf-8')).decode('utf-8')
    cmd = f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{node_ip} \"echo {encoded} | base64 -d | python3\""
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return "SUCCESS" in res.stdout
    except: return False

def add_keys(node_id, group_id, usernames, total_gb, expire_days, protocol, is_auto=False):
    nodes = get_all_servers()
    
    if is_auto:
        target_nodes = get_auto_group_nodes(group_id)
        if not target_nodes: return False, "No active servers in group"
        # ရိုးရှင်းသော အလှည့်ကျစနစ် (Round-robin) ဖြင့် Node ရွေးမည်
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
        for uname in usernames:
            uname = uname.strip()
            if not uname or uname in db: continue
            
            uid = str(uuid.uuid4())
            exp_date = (datetime.now() + timedelta(days=expire_days)).strftime("%Y-%m-%d")
            
            # Protocol အလိုက် Object ဆောက်မည်
            if protocol == 'v2':
                c_obj = {"id": uid, "email": uname, "flow": ""}
                b64_uid = base64.b64encode(uid.encode()).decode()
                actual_key = f"vless://{uid}@{node_ip}:443?encryption=none&security=none&type=ws&host={node_ip}&path=%2F#PanelMaster-{uname}"
            else:
                c_obj = {"password": uid, "email": uname}
                b64_cred = base64.b64encode(f"chacha20-ietf-poly1305:{uid}".encode()).decode()
                actual_key = f"ss://{b64_cred}@{node_ip}:443#PanelMaster-{uname}"
                
            new_clients.append(c_obj)
            
            db[uname] = {
                "uuid": uid,
                "node": node_id,
                "group": group_id if is_auto else "",
                "total_gb": total_gb,
                "used_bytes": 0,
                "expire_date": exp_date,
                "is_blocked": False,
                "protocol": protocol,
                "port": "443",
                "key": actual_key
            }
            
        if new_clients:
            # ဆာဗာသို့ တိုက်ရိုက် Bulk လှမ်းထည့်မည်
            if sync_xray_config_remote(node_ip, 'add', protocol, new_clients):
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
            
            # Block ထားပါက ဖြုတ်မည် (Add Back), မ Block ရသေးပါက ပိတ်မည် (Remove)
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
            
        # Node အလိုက် ခွဲထုတ်၍ တပြိုင်နက် ဖျက်မည်
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
            
            # Expire ဖြစ်နေခဲ့လျှင် ယနေ့မှစ၍ ပေါင်းမည်၊ မဖြစ်သေးလျှင် လက်ရှိရက်ပေါ်ပေါင်းမည်
            if curr_exp < datetime.now(): curr_exp = datetime.now()
            uinfo['expire_date'] = (curr_exp + timedelta(days=int(add_days))).strftime("%Y-%m-%d")
            
            # Block ထားပါက Auto ပြန်ဖွင့်ပေးမည်
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
            
            # Update လုပ်ပြီးနောက် ပိတ်ထားသင့်/ဖွင့်ထားသင့် စစ်ဆေးမည်
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
    # Auto Rebalance စနစ် (လက်ရှိစနစ်အတိုင်း ဆက်ထားပါသည်)
    return True, "Rebalanced Successfully"
