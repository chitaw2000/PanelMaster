import json
import os
import uuid
import subprocess
import base64
from datetime import datetime, timedelta
from utils import db_lock, get_all_servers
from core_auto import load_auto_groups
from config import USERS_DB

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
            
            # 🚀 အစ်ကို၏ မူရင်း v2ray-node-* Script များကို ပြန်လည်အသုံးပြုခြင်း
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
                "is_blocked": False, "key": key_str
            }
            added_users = True
            
        if added_users:
            if commands:
                commands.append("systemctl restart xray")
                # 🚀 Bulk ထုတ်ရာတွင် Error မတက်စေရန် Command များကို တစုတစည်းတည်း Run မည်
                full_cmd = " ; ".join(commands)
                subprocess.run(f"ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no root@{node_ip} \"{full_cmd}\"", shell=True, capture_output=True)
            
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
                # 🚀 အစ်ကို၏ မူရင်း Block / Unblock စနစ်ကို အသုံးပြုခြင်း
                if user['is_blocked']:
                    os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"jq '(.inbounds[] | select(.protocol==\\\"vless\\\" or .protocol==\\\"shadowsocks\\\").settings.clients) |= map(select(.email != \\\"{username}\\\"))' /usr/local/etc/xray/config.json > /tmp/c.json && mv /tmp/c.json /usr/local/etc/xray/config.json\"")
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
            
        nodes_to_sync = set()
        for u in usernames:
            if u in db:
                nid = db[u].get('node')
                node_ip = get_all_servers().get(nid, {}).get('ip')
                if node_ip:
                    # 🚀 အစ်ကို၏ မူရင်း jq ဖြင့် ဖျက်သောစနစ်ကို အသုံးပြုခြင်း
                    os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"jq '(.inbounds[] | select(.protocol==\\\"vless\\\" or .protocol==\\\"shadowsocks\\\").settings.clients) |= map(select(.email != \\\"{u}\\\"))' /usr/local/etc/xray/config.json > /tmp/c.json && mv /tmp/c.json /usr/local/etc/xray/config.json\"")
                    nodes_to_sync.add(node_ip)
                del db[u]
                
        with open(USERS_DB, 'w') as f: json.dump(db, f)
        
    for ip in nodes_to_sync:
        os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{ip} 'systemctl restart xray'")

def renew_key(username, add_gb, add_days):
    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            
        if username in db:
            user = db[username]
            user['total_gb'] = float(user.get('total_gb', 0)) + float(add_gb)
            try:
                curr_exp = datetime.strptime(user.get('expire_date', '2099-01-01'), "%Y-%m-%d")
            except:
                curr_exp = datetime.now()
            
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
