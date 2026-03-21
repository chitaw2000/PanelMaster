import json
import os
import uuid
import base64
import urllib.parse
from datetime import datetime, timedelta

from utils import db_lock, get_all_servers
from core_auto import find_available_node, load_auto_groups, save_auto_groups
from core_engine import execute_ssh_bg, get_safe_delete_cmd, get_block_cmd

try:
    from config import USERS_DB, NODES_LIST, NODES_DB
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"
    NODES_DB = "/root/PanelMaster/nodes_db.json"

def get_robust_ip(node_id):
    nodes = get_all_servers()
    if node_id in nodes:
        info = nodes[node_id]
        if info.get('ip'):
            return str(info['ip']).strip()
    
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: 
                    continue
                target_str = str(node_id)
                if line.startswith(target_str + "|") or line.startswith(target_str + " "):
                    parts = line.replace('|', ' ').split()
                    return parts[-1].strip()
    return None

def _save_historical_traffic(node_id, used_bytes):
    if not node_id: return
    if used_bytes <= 0: return
        
    try:
        ndb = {}
        if os.path.exists(NODES_DB):
            with open(NODES_DB, 'r') as f: ndb = json.load(f)
                
        if node_id not in ndb:
            ndb[node_id] = {"used_bytes": 0, "limit_tb": 0, "health": "green"}
            
        ndb[node_id]["used_bytes"] = float(ndb[node_id].get("used_bytes", 0)) + float(used_bytes)
        
        with open(NODES_DB, 'w') as f: json.dump(ndb, f, indent=4)
    except Exception:
        pass

def sanitize_usernames(raw_list):
    clean_list = []
    for user in raw_list:
        if not user: continue
        clean_user = str(user).strip().replace(" ", "_").replace("\r", "").replace("\n", "")
        if clean_user: clean_list.append(clean_user)
    return clean_list

def add_keys(node_id, group_id, raw_usernames, gb, days, proto, is_auto=False):
    usernames = sanitize_usernames(raw_usernames)
    if len(usernames) == 0: 
        return False, "❌ No valid usernames provided!"

    db = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except Exception: pass

        existing_ids = []
        for user_info in db.values():
            if isinstance(user_info, dict):
                key_id = user_info.get('key_id', '')
                if str(key_id).isdigit():
                    existing_ids.append(int(key_id))
                    
        next_id = max(existing_ids) + 1 if existing_ids else 1
        exp_date = datetime.now() + timedelta(days=days)
        exp = exp_date.strftime("%Y-%m-%d")
        
        cmds_by_ip = {}
        max_p_by_node = {} 
        
        for user_info in db.values():
            if isinstance(user_info, dict) and user_info.get('protocol') == 'out':
                nid = user_info.get('node')
                try: p = int(user_info.get('port', 10000))
                except ValueError: p = 10000
                max_p_by_node[nid] = max(max_p_by_node.get(nid, 10000), p)

        for username in usernames:
            if username in db: 
                continue
            
            if is_auto:
                target_node, target_ip = find_available_node(group_id, 1, current_db=db)
                if not target_node:
                    if len(cmds_by_ip) == 0:
                        return False, "❌ Error: Limit Reached! No space available in any server for this Auto Node."
                    break 
            else:
                target_node = node_id
                target_ip = get_robust_ip(node_id)
                if not target_ip: 
                    return False, "❌ Error: Node Server is offline or not found!"

            target_ip = str(target_ip).strip()
            max_p = max_p_by_node.get(target_node, 10000)

            uid = str(uuid.uuid4()).strip()
            safe_u = urllib.parse.quote(username)
            
            if target_ip not in cmds_by_ip:
                cmds_by_ip[target_ip] = []
                
            if proto == 'v2':
                port = "443"
                k = f"vless://{uid}@{target_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
                cmd = f"/usr/local/bin/v2ray-node-add-vless {username} {uid}"
                cmds_by_ip[target_ip].append(cmd)
            else:
                max_p += 1
                max_p_by_node[target_node] = max_p  
                port = str(max_p)
                raw_ss = f"chacha20-ietf-poly1305:{uid}@{target_ip}:{port}"
                ss_conf = base64.b64encode(raw_ss.encode('utf-8')).decode('utf-8').strip()
                k = f"ss://{ss_conf}#{safe_u}"
                
                cmd = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {port}"
                cmds_by_ip[target_ip].append(cmd)
                ufw_cmd = f"ufw allow {port}/tcp >/dev/null 2>&1 && ufw allow {port}/udp >/dev/null 2>&1"
                cmds_by_ip[target_ip].append(ufw_cmd)
            
            db[username] = {
                "node": target_node, "group": group_id, "protocol": proto, "uuid": uid, 
                "port": port, "total_gb": float(gb), "expire_date": exp, 
                "used_bytes": 0, "last_raw_bytes": 0, "is_blocked": False, "is_online": False, 
                "key": k, "key_id": next_id
            }
            next_id += 1
        
        if cmds_by_ip:
            with open(USERS_DB, 'w') as f: 
                json.dump(db, f, indent=4)
            
            for ip, ip_cmds in cmds_by_ip.items():
                ip_cmds.append("systemctl restart xray")
                execute_ssh_bg(ip, ip_cmds)
                
        return True, "Success"

def toggle_key(username):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: 
                db = json.load(f)
                
            if username in db:
                user = db[username]
                
                if user.get('is_blocked', False) == False:
                    user['is_blocked'] = True
                    user['is_online'] = False
                    is_blocking = True
                else:
                    user['is_blocked'] = False
                    is_blocking = False
                    
                ip = get_robust_ip(user.get('node'))
                if ip:
                    uid = user.get('uuid')
                    protocol = user.get('protocol', 'v2')
                    port = user.get('port', '443')
                    
                    if is_blocking:
                        cmd = get_block_cmd(username, protocol, port)
                    else:
                        if protocol == 'v2': 
                            cmd = f"/usr/local/bin/v2ray-node-add-vless {username} {uid}"
                        else: 
                            cmd = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {port}"
                            
                    execute_ssh_bg(str(ip).strip(), [cmd, "systemctl restart xray"])
                    
                with open(USERS_DB, 'w') as f: 
                    json.dump(db, f, indent=4)

def edit_key(username, total_gb, expire_date):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                if total_gb is not None: db[username]['total_gb'] = float(total_gb)
                if expire_date: db[username]['expire_date'] = expire_date
                
                exp_date = datetime.strptime(db[username]['expire_date'], "%Y-%m-%d")
                if datetime.now() <= exp_date and db[username].get('is_blocked', False) == True:
                    tot_gb = float(db[username].get('total_gb', 0))
                    max_bytes = tot_gb * (1024**3) if tot_gb > 0 else float('inf')
                    
                    if float(db[username].get('used_bytes', 0)) < max_bytes:
                        db[username]['is_blocked'] = False
                        ip = get_robust_ip(db[username].get('node'))
                        if ip:
                            uid = db[username]['uuid']
                            protocol = db[username]['protocol']
                            port = db[username]['port']
                            if protocol == 'v2':
                                cmd = f"/usr/local/bin/v2ray-node-add-vless {username} {uid}"
                            else:
                                cmd = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {port}"
                            execute_ssh_bg(str(ip).strip(), [cmd, "systemctl restart xray"])

                with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)

def renew_key(username, add_gb, add_days):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                db[username]['total_gb'] = float(add_gb)
                db[username]['days'] = int(add_days)
                db[username]['expire_date'] = (datetime.now() + timedelta(days=int(add_days))).strftime("%Y-%m-%d")
                db[username]['used_bytes'] = 0
                db[username]['last_raw_bytes'] = 0
                db[username]['is_blocked'] = False
                db[username]['is_online'] = False
                
                ip = get_robust_ip(db[username].get('node'))
                if ip:
                    uid = db[username]['uuid']
                    protocol = db[username]['protocol']
                    port = db[username]['port']
                    if protocol == 'v2':
                        cmd = f"/usr/local/bin/v2ray-node-add-vless {username} {uid}"
                    else:
                        cmd = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {port}"
                    execute_ssh_bg(str(ip).strip(), [cmd, "systemctl restart xray"])
                
                with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)

def delete_key(username):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                info = db[username]
                node_id = info.get('node')
                ip = get_robust_ip(node_id)
                
                try:
                    used_bytes = float(info.get('used_bytes', 0))
                    _save_historical_traffic(node_id, used_bytes)
                except Exception:
                    pass

                if ip:
                    protocol = info.get('protocol', 'v2')
                    port = info.get('port', '443')
                    cmd = get_safe_delete_cmd(username, protocol, port)
                    execute_ssh_bg(str(ip).strip(), [cmd, "systemctl restart xray"])
                    
                del db[username]
                with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)

def bulk_delete_keys(usernames):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            cmds_by_ip = {}
            for uname in usernames:
                if uname in db:
                    info = db[uname]
                    node_id = info.get('node')
                    
                    try:
                        used_bytes = float(info.get('used_bytes', 0))
                        _save_historical_traffic(node_id, used_bytes)
                    except Exception:
                        pass

                    ip = get_robust_ip(node_id)
                    if ip:
                        ip = str(ip).strip()
                        protocol = info.get('protocol', 'v2')
                        port = info.get('port', '443')
                        cmd = get_safe_delete_cmd(uname, protocol, port)
                        
                        if ip not in cmds_by_ip:
                            cmds_by_ip[ip] = []
                        cmds_by_ip[ip].append(cmd)
                    del db[uname]
                    
            with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)
            
            for ip, cmds in cmds_by_ip.items():
                cmds.append("systemctl restart xray")
                execute_ssh_bg(ip, cmds)

def rebalance_auto_node(group_id, new_limit, specific_node=None):
    groups = load_auto_groups()
    if group_id not in groups: 
        return False, "Group not found"

    groups[group_id]["limit"] = new_limit
    for nid in groups[group_id]["nodes"]:
        if specific_node and nid != specific_node: 
            continue
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
            if specific_node and nid != specific_node: 
                continue
            users_on_node = [uname for uname, info in db.items() if info.get('node') == nid]
            if len(users_on_node) > new_limit:
                excess_users.extend(users_on_node[new_limit:])

        if len(excess_users) == 0: 
            return True, "Success"

        cmds_by_ip = {}
        migrated_count = 0
        
        for uname in excess_users:
            uinfo = db[uname]
            old_node = uinfo.get('node')
            old_ip = str(get_robust_ip(old_node)).strip()
            old_port = uinfo.get('port')
            proto = uinfo.get('protocol')
            old_key_id = uinfo.get('key_id') 
            
            new_node_id, new_node_ip = find_available_node(group_id, 1, current_db=db)
            if not new_node_id: 
                break
            
            new_node_ip = str(new_node_ip).strip()
            
            cmd_del = get_safe_delete_cmd(uname, proto, old_port)
            if old_ip not in cmds_by_ip:
                cmds_by_ip[old_ip] = []
            cmds_by_ip[old_ip].append(cmd_del)
            
            used_ports = [int(i.get('port', 10000)) for i in db.values() if isinstance(i, dict) and i.get('protocol') == 'out' and i.get('node') == new_node_id]
            new_port = str(max(used_ports) + 1) if used_ports else "10001"
            
            uid = uinfo.get('uuid')
            safe_u = urllib.parse.quote(uname)

            if new_node_ip not in cmds_by_ip:
                cmds_by_ip[new_node_ip] = []

            if proto == 'v2':
                new_port = "443"
                k = f"vless://{uid}@{new_node_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
                cmd_add = f"/usr/local/bin/v2ray-node-add-vless {uname} {uid}"
                cmds_by_ip[new_node_ip].append(cmd_add)
            else:
                raw_ss = f"chacha20-ietf-poly1305:{uid}@{new_node_ip}:{new_port}"
                ss_conf = base64.b64encode(raw_ss.encode('utf-8')).decode('utf-8').strip()
                k = f"ss://{ss_conf}#{safe_u}"
                cmd_add = f"/usr/local/bin/v2ray-node-add-out {uname} {uid} {new_port}"
                cmds_by_ip[new_node_ip].append(cmd_add)
                ufw_cmd = f"ufw allow {new_port}/tcp >/dev/null 2>&1 && ufw allow {new_port}/udp >/dev/null 2>&1"
                cmds_by_ip[new_node_ip].append(ufw_cmd)

            db[uname]['node'] = new_node_id
            db[uname]['port'] = new_port
            db[uname]['key'] = k
            if old_key_id: 
                db[uname]['key_id'] = old_key_id 
            
            migrated_count += 1
            
        with open(USERS_DB, 'w') as f: 
            json.dump(db, f, indent=4)

        for ip, cmds in cmds_by_ip.items():
            cmds.append("systemctl restart xray")
            execute_ssh_bg(ip, cmds)
            
        if migrated_count < len(excess_users):
            return False, f"Limit Updated. Migrated {migrated_count} keys. Failed to migrate {len(excess_users) - migrated_count} keys (No space)."
        return True, "Success"
