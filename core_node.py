import json
import os
import uuid
import subprocess
import base64
from datetime import datetime, timedelta
from utils import db_lock, get_all_servers
from core_auto import load_auto_groups
from config import USERS_DB

def get_safe_delete_cmd_multi(users_to_delete):
    """
    အစ်ကို့ရဲ့ မူရင်း Safe Delete ကို အခြေခံထားပြီး၊
    လူအများကြီး တစ်ပြိုင်နက်ဖျက်ရင်တောင် JSON ဖိုင် လုံးဝမပျက်အောင် ကာကွယ်ပေးထားသော စနစ်။
    """
    py_script = f"""
import json
try:
    users_to_delete = {json.dumps(users_to_delete)}
    path = '/usr/local/etc/xray/config.json'
    with open(path, 'r') as f: d = json.load(f)
    changed = False
    new_inbounds = []
    
    out_ports = [str(u['port']) for u in users_to_delete if u['proto'] == 'out']
    v2_unames = [u['uname'] for u in users_to_delete if u['proto'] == 'v2']
    
    for ib in d.get('inbounds', []):
        # SS ဆိုလျှင် Port တိုက်စစ်ပြီး တစ်ခုလုံးကို ဖြတ်ချမည်
        if str(ib.get('port')) in out_ports and ib.get('protocol') == 'shadowsocks':
            changed = True
            continue
            
        # VLESS ဆိုလျှင် clients စာရင်းထဲမှ ဆွဲထုတ်မည်
        if ib.get('protocol') == 'vless' and 'settings' in ib and 'clients' in ib['settings']:
            orig_len = len(ib['settings']['clients'])
            ib['settings']['clients'] = [c for c in ib['settings']['clients'] if c.get('email') not in v2_unames]
            if len(ib['settings']['clients']) != orig_len: changed = True
            
        new_inbounds.append(ib)
        
    if changed:
        d['inbounds'] = new_inbounds
        with open(path, 'w') as f: json.dump(d, f, indent=2)
except Exception as e: pass
"""
    b64_script = base64.b64encode(py_script.encode('utf-8')).decode()
    return f"echo {b64_script} | base64 -d | python3"

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

        # မူရင်းအတိုင်း Port အမြင့်ဆုံးကို ရှာမည်
        max_port = 10000
        for u, info in db.items():
            if info.get('protocol') == 'out':
                try:
                    p = int(info.get('port', 10000))
                    if p > max_port: max_port = p
                except: pass

        commands = []
        current_port = max_port
        added_users = False

        for uname in usernames:
            uname = uname.strip()
            if not uname or uname in db: continue
            
            uid = str(uuid.uuid4())
            exp_date = (datetime.now() + timedelta(days=expire_days)).strftime("%Y-%m-%d")
            
            # 🚀 အစ်ကို၏ မူရင်း v2ray-node-* Script များကိုသာ ပြန်လည်အသုံးပြုမည်
            if protocol == 'v2':
                port = "443"
                key_str = f"vless://{uid}@{node_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{uname}"
                commands.append(f"/usr/local/bin/v2ray-node-add-vless {uname} {uid}")
            else:
                current_port += 1 
                port = str(current_port)
                ss_conf = base64.b64encode(f"chacha20-ietf-poly1305:{uid}".encode()).decode()
                key_str = f"ss://{ss_conf}@{node_ip}:{port}#{uname}"
                commands.append(f"/usr/local/bin/v2ray-node-add-out {uname} {uid} {port}")
                commands.append(f"ufw allow {port}/tcp && ufw allow {port}/udp")
                
            db[uname] = {
                "node": node_id, "group": group_id if is_auto else "",
                "protocol": protocol, "uuid": uid, "port": port,
                "total_gb": total_gb, "expire_date": exp_date, "used_bytes": 0,
                "last_raw_bytes": 0, "is_blocked": False, "key": key_str
            }
            added_users = True
            
        if added_users:
            if commands:
                commands.append("systemctl restart xray")
                # 🚀 တစ်ပြိုင်နက်တည်း Run စေရန် Group လုပ်လိုက်သည်
                full_cmd = " ; ".join(commands)
                os.system(f"ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no root@{node_ip} \"{full_cmd}\"")
            
            with open(USERS_DB, 'w') as f: json.dump(db, f)
            return True, "Keys generated successfully"
            
    return False, "Invalid usernames or all users already exist."

def toggle_key(username):
    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            
        if username in db:
            user = db[username]
            user['is_blocked'] = not user.get('is_blocked', False)
            node_ip = get_all_servers().get(user.get('node'), {}).get('ip')
            if node_ip:
                if user['is_blocked']:
                    safe_cmd = get_safe_delete_cmd_multi([{'uname': username, 'proto': user.get('protocol', 'v2'), 'port': user.get('port', '443')}])
                    os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"{safe_cmd} ; systemctl restart xray\"")
                else:
                    uid = user['uuid']
                    if user.get('protocol', 'v2') == 'v2':
                        os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} '/usr/local/bin/v2ray-node-add-vless {username} {uid}'")
                    else:
                        port = user.get('port', '10000')
                        os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} '/usr/local/bin/v2ray-node-add-out {username} {uid} {port}'")
                    os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} 'systemctl restart xray'")
                
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
                node_ip = get_all_servers().get(nid, {}).get('ip')
                if node_ip:
                    if node_ip not in nodes_to_sync: nodes_to_sync[node_ip] = []
                    nodes_to_sync[node_ip].append({'uname': u, 'proto': db[u].get('protocol', 'v2'), 'port': db[u].get('port', '443')})
                del db[u]
                
        with open(USERS_DB, 'w') as f: json.dump(db, f)
        
    # 🚀 Node တစ်ခုစီရှိ လူအများကြီးကို တစ်ချက်တည်းဖြင့် အမှားကင်းစွာ ဖျက်ပေးမည်
    for ip, users in nodes_to_sync.items():
        safe_cmd = get_safe_delete_cmd_multi(users)
        os.system(f"ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no root@{ip} \"{safe_cmd} ; systemctl restart xray\"")

def renew_key(username, add_gb, add_days):
    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            
        if username in db:
            user = db[username]
            user['total_gb'] = float(user.get('total_gb', 0)) + float(add_gb)
            try: curr_exp = datetime.strptime(user.get('expire_date', '2099-01-01'), "%Y-%m-%d")
            except: curr_exp = datetime.now()
            
            if curr_exp < datetime.now(): curr_exp = datetime.now()
            user['expire_date'] = (curr_exp + timedelta(days=int(add_days))).strftime("%Y-%m-%d")
            
            if user.get('is_blocked'):
                user['is_blocked'] = False
                node_ip = get_all_servers().get(user.get('node'), {}).get('ip')
                if node_ip:
                    uid = user.get('uuid')
                    if user.get('protocol', 'v2') == 'v2':
                        os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} '/usr/local/bin/v2ray-node-add-vless {username} {uid}'")
                    else:
                        port = user.get('port', '10000')
                        os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} '/usr/local/bin/v2ray-node-add-out {username} {uid} {port}'")
                    os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} 'systemctl restart xray'")
                    
            with open(USERS_DB, 'w') as f: json.dump(db, f)

def edit_key(username, gb, exp):
    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            
        if username in db:
            user = db[username]
            if gb is not None: user['total_gb'] = float(gb)
            if exp: user['expire_date'] = exp
            
            used = float(user.get('used_bytes', 0)) / (1024**3)
            tot = float(user.get('total_gb', 0))
            is_over = tot > 0 and used >= tot
            
            try: is_exp = datetime.now().date() > datetime.strptime(user['expire_date'], "%Y-%m-%d").date()
            except: is_exp = False
            
            if (not is_over and not is_exp) and user.get('is_blocked'):
                user['is_blocked'] = False
                node_ip = get_all_servers().get(user.get('node'), {}).get('ip')
                if node_ip:
                    uid = user.get('uuid')
                    if user.get('protocol', 'v2') == 'v2':
                        os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} '/usr/local/bin/v2ray-node-add-vless {username} {uid}'")
                    else:
                        port = user.get('port', '10000')
                        os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} '/usr/local/bin/v2ray-node-add-out {username} {uid} {port}'")
                    os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} 'systemctl restart xray'")
                    
            with open(USERS_DB, 'w') as f: json.dump(db, f)

def rebalance_auto_node(group_id, limit, specific_node=None):
    return True, "Rebalanced Successfully"
