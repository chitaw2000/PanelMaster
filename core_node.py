import json
import os
import uuid
import base64
import urllib.parse
from datetime import datetime, timedelta

from utils import db_lock, get_all_servers
from core_auto import find_available_node, load_auto_groups, save_auto_groups
from core_engine import execute_ssh_bg, get_block_cmd, get_unblock_cmd, get_safe_delete_cmd

try:
    from config import USERS_DB, NODES_LIST, NODES_DB
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"
    NODES_DB = "/root/PanelMaster/nodes_db.json"

def get_robust_ip(node_id):
    nodes = get_all_servers()
    if node_id in nodes:
        node_info = nodes[node_id]
        if node_info.get('ip'):
            return str(node_info['ip']).strip()
    
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
    if not node_id:
        return
    if used_bytes <= 0:
        return
        
    try:
        ndb = {}
        if os.path.exists(NODES_DB):
            with open(NODES_DB, 'r') as f:
                ndb = json.load(f)
                
        if node_id not in ndb:
            ndb[node_id] = {
                "used_bytes": 0, 
                "limit_tb": 0, 
                "health": "green"
            }
            
        current_used = float(ndb[node_id].get("used_bytes", 0))
        ndb[node_id]["used_bytes"] = current_used + float(used_bytes)
        
        with open(NODES_DB, 'w') as f:
            json.dump(ndb, f)
    except Exception as e:
        pass

def sanitize_usernames(raw_list):
    clean_list = []
    for user in raw_list:
        if not user: 
            continue
        clean_user = str(user).strip()
        clean_user = clean_user.replace(" ", "_")
        clean_user = clean_user.replace("\r", "")
        clean_user = clean_user.replace("\n", "")
        
        if clean_user: 
            clean_list.append(clean_user)
    return clean_list

def add_keys(node_id, group_id, raw_usernames, gb, days, proto, is_auto=False):
    usernames = sanitize_usernames(raw_usernames)
    if len(usernames) == 0: 
        return False, "❌ No valid usernames provided!"

    db = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: 
                    db = json.load(f)
            except Exception as e: 
                pass

        existing_ids = []
        for user_info in db.values():
            if isinstance(user_info, dict):
                key_id = user_info.get('key_id', '')
                if str(key_id).isdigit():
                    existing_ids.append(int(key_id))
                    
        if len(existing_ids) > 0:
            next_id = max(existing_ids) + 1 
        else:
            next_id = 1

        expire_date = datetime.now() + timedelta(days=days)
        expire_date_str = expire_date.strftime("%Y-%m-%d")
        
        cmds_by_ip = {}
        max_port_by_node = {} 
        
        for user_info in db.values():
            if isinstance(user_info, dict):
                if user_info.get('protocol') == 'out':
                    current_node = user_info.get('node')
                    current_port = user_info.get('port', 10000)
                    
                    try:
                        port_num = int(current_port)
                    except ValueError:
                        port_num = 10000
                        
                    if current_node not in max_port_by_node:
                        max_port_by_node[current_node] = 10000
                        
                    if port_num > max_port_by_node[current_node]:
                        max_port_by_node[current_node] = port_num

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

            if target_node not in max_port_by_node:
                max_port_by_node[target_node] = 10000
            current_max_port = max_port_by_node[target_node]

            uid = str(uuid.uuid4()).strip()
            safe_username = urllib.parse.quote(username)
            
            if proto == 'v2':
                port = "443"
                key_string = f"vless://{uid}@{target_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_username}"
                command = f"/usr/local/bin/v2ray-node-add-vless {username} {uid}"
            else:
                current_max_port = current_max_port + 1
                max_port_by_node[target_node] = current_max_port
                
                port = str(current_max_port)
                raw_ss = f"chacha20-ietf-poly1305:{uid}@{target_ip}:{port}"
                ss_conf = base64.b64encode(raw_ss.encode('utf-8')).decode('utf-8').strip()
                key_string = f"ss://{ss_conf}#{safe_username}"
                command = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {port} ; ufw allow {port}/tcp >/dev/null 2>&1 && ufw allow {port}/udp >/dev/null 2>&1"
            
            if target_ip not in cmds_by_ip:
                cmds_by_ip[target_ip] = []
                
            cmds_by_ip[target_ip].append(command)
            
            db[username] = {
                "node": target_node, 
                "group": group_id, 
                "protocol": proto, 
                "uuid": uid, 
                "port": port, 
                "total_gb": float(gb), 
                "expire_date": expire_date_str, 
                "used_bytes": 0, 
                "last_raw_bytes": 0, 
                "is_blocked": False, 
                "is_online": False, 
                "key": key_string, 
                "key_id": next_id
            }
            next_id = next_id + 1
        
        if len(cmds_by_ip) > 0:
            with open(USERS_DB, 'w') as f: 
                json.dump(db, f)
            
            for ip, commands in cmds_by_ip.items():
                commands.append("systemctl restart xray")
                execute_ssh_bg(ip, commands)
                
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
                    is_blocking_action = True
                else:
                    user['is_blocked'] = False
                    is_blocking_action = False
                    
                ip = get_robust_ip(user.get('node'))
                if ip:
                    uid = user.get('uuid')
                    protocol = user.get('protocol', 'v2')
                    port = user.get('port', '443')
                    
                    if is_blocking_action == True: 
                        cmd = get_block_cmd(username, protocol, port, uid)
                    else:
                        cmd = get_unblock_cmd(username, protocol, port, uid)
                    
                    execute_ssh_bg(str(ip).strip(), [cmd, "systemctl restart xray"])
                    
                with open(USERS_DB, 'w') as f: 
                    json.dump(db, f)

def edit_key(username, total_gb, expire_date):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: 
                db = json.load(f)
            if username in db:
                if total_gb is not None: 
                    db[username]['total_gb'] = float(total_gb)
                if expire_date: 
                    db[username]['expire_date'] = expire_date
                with open(USERS_DB, 'w') as f: 
                    json.dump(db, f)

def renew_key(username, add_gb, add_days):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: 
                db = json.load(f)
            if username in db:
                db[username]['total_gb'] = float(add_gb)
                db[username]['days'] = int(add_days)
                new_exp = datetime.now() + timedelta(days=int(add_days))
                db[username]['expire_date'] = new_exp.strftime("%Y-%m-%d")
                db[username]['used_bytes'] = 0
                db[username]['last_raw_bytes'] = 0
                db[username]['is_blocked'] = False
                db[username]['is_online'] = False
                with open(USERS_DB, 'w') as f: 
                    json.dump(db, f)

def delete_key(username):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: 
                db = json.load(f)
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
                    uid = info.get('uuid')
                    protocol = info.get('protocol', 'v2')
                    port = info.get('port', '443')
                    
                    cmd = get_safe_delete_cmd(username, protocol, port, uid)
                    execute_ssh_bg(str(ip).strip(), [cmd, "systemctl restart xray"])
                    
                del db[username]
                with open(USERS_DB, 'w') as f: 
                    json.dump(db, f)

def bulk_delete_keys(usernames):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: 
                db = json.load(f)
                
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
                        uid = info.get('uuid')
                        protocol = info.get('protocol', 'v2')
                        port = info.get('port', '443')
                        
                        cmd = get_safe_delete_cmd(uname, protocol, port, uid)
                        
                        if ip not in cmds_by_ip:
                            cmds_by_ip[ip] = []
                        cmds_by_ip[ip].append(cmd)
                        
                    del db[uname]
                    
            with open(USERS_DB, 'w') as f: 
                json.dump(db, f)
            
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
            with open(USERS_DB, 'r') as f: 
                db = json.load(f)

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
            old_uuid = uinfo.get('uuid')
            
            new_node_id, new_node_ip = find_available_node(group_id, 1, current_db=db)
            if not new_node_id: 
                break
            
            new_node_ip = str(new_node_ip).strip()
            
            cmd_del = get_safe_delete_cmd(uname, proto, old_port, old_uuid)
            
            if old_ip not in cmds_by_ip:
                cmds_by_ip[old_ip] = []
            cmds_by_ip[old_ip].append(cmd_del)
            
            used_ports = []
            for i in db.values():
                if isinstance(i, dict) and i.get('protocol') == 'out' and i.get('node') == new_node_id:
                    try:
                        used_ports.append(int(i.get('port', 10000)))
                    except:
                        pass
                        
            if len(used_ports) > 0:
                new_port = str(max(used_ports) + 1) 
            else:
                new_port = "10001"
            
            safe_u = urllib.parse.quote(uname)

            if proto == 'v2':
                new_port = "443"
                k = f"vless://{old_uuid}@{new_node_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
                cmd_add = f"/usr/local/bin/v2ray-node-add-vless {uname} {old_uuid}"
            else:
                raw_ss = f"chacha20-ietf-poly1305:{old_uuid}@{new_node_ip}:{new_port}"
                ss_conf = base64.b64encode(raw_ss.encode('utf-8')).decode('utf-8').strip()
                k = f"ss://{ss_conf}#{safe_u}"
                cmd_add = f"/usr/local/bin/v2ray-node-add-out {uname} {old_uuid} {new_port}"
                
                if new_node_ip not in cmds_by_ip:
                    cmds_by_ip[new_node_ip] = []
                cmds_by_ip[new_node_ip].append(f"ufw allow {new_port}/tcp && ufw allow {new_port}/udp")

            if new_node_ip not in cmds_by_ip:
                cmds_by_ip[new_node_ip] = []
            cmds_by_ip[new_node_ip].append(cmd_add)
            
            db[uname]['node'] = new_node_id
            db[uname]['port'] = new_port
            db[uname]['key'] = k
            if old_key_id: 
                db[uname]['key_id'] = old_key_id 
            
            migrated_count += 1
            
        with open(USERS_DB, 'w') as f: 
            json.dump(db, f)

        for ip, cmds in cmds_by_ip.items():
            cmds.append("systemctl restart xray")
            execute_ssh_bg(ip, cmds)
            
        if migrated_count < len(excess_users):
            return False, f"Limit Updated. Migrated {migrated_count} keys. Failed to migrate {len(excess_users) - migrated_count} keys (No space)."
        return True, "Success"
