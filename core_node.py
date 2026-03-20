import json, os, uuid, base64, urllib.parse
from datetime import datetime, timedelta
from utils import db_lock, get_all_servers
from core_auto import find_available_node, load_auto_groups, save_auto_groups

# 🚀 ချိတ်ဆက်မှု Error ကင်းစေရန် အသေချာဆုံး Import
from core_engine import execute_ssh_bg, get_safe_delete_cmd

try:
    from config import USERS_DB
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"

def sanitize_usernames(raw_list):
    clean = []
    for u in raw_list:
        if not u: continue
        u = str(u).strip().replace(" ", "_").replace("\r", "").replace("\n", "")
        if u: clean.append(u)
    return clean

def add_keys(node_id, group_id, raw_usernames, gb, days, proto, is_auto=False):
    usernames = sanitize_usernames(raw_usernames)
    if not usernames: return False, "❌ No valid usernames provided!"

    db = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: pass

        if is_auto:
            target_node, target_ip = find_available_node(group_id, len(usernames), current_db=db)
            if not target_node: return False, "❌ Error: Limit Reached! No space available in any server for this Auto Node."
        else:
            target_node = node_id
            target_ip = get_all_servers().get(node_id, {}).get('ip')
            if not target_ip: return False, "❌ Error: Node Server is offline or not found!"

        target_ip = str(target_ip).strip()
        used_ports = [int(i.get('port', 10000)) for i in db.values() if i.get('protocol') == 'out' and i.get('node') == target_node]
        max_p = max(used_ports) if used_ports else 10000

        existing_ids = [int(u.get('key_id', 0)) for u in db.values() if isinstance(u, dict) and str(u.get('key_id', '')).isdigit()]
        next_id = max(existing_ids) + 1 if existing_ids else 1

        exp = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
        cmds = []
        
        for u in usernames:
            if u in db: continue
            uid = str(uuid.uuid4()).strip()
            safe_u = urllib.parse.quote(u)
            
            if proto == 'v2':
                port = "443"
                k = f"vless://{uid}@{target_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
                cmds.append(f"/usr/local/bin/v2ray-node-add-vless {u} {uid}")
            else:
                max_p += 1; port = str(max_p)
                raw_ss = f"chacha20-ietf-poly1305:{uid}@{target_ip}:{port}"
                ss_conf = base64.b64encode(raw_ss.encode('utf-8')).decode('utf-8').strip()
                k = f"ss://{ss_conf}#{safe_u}"
                cmds.append(f"/usr/local/bin/v2ray-node-add-out {u} {uid} {port} ; ufw allow {port}/tcp && ufw allow {port}/udp")
                
            db[u] = {
                "node": target_node, "group": group_id, "protocol": proto, "uuid": uid, 
                "port": port, "total_gb": float(gb), "expire_date": exp, 
                "used_bytes": 0, "last_raw_bytes": 0, "is_blocked": False, "is_online": False, 
                "key": k, "key_id": next_id
            }
            next_id += 1
        
        if cmds:
            with open(USERS_DB, 'w') as f: json.dump(db, f)
            cmds.append("systemctl restart xray")
            execute_ssh_bg(target_ip, cmds)
            
    return True, "Success"

def toggle_key(username):
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
                    execute_ssh_bg(str(ip).strip(), [cmd, "systemctl restart xray"])
                with open(USERS_DB, 'w') as f: json.dump(db, f)

def edit_key(username, total_gb, expire_date):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                if total_gb is not None: db[username]['total_gb'] = float(total_gb)
                if expire_date: db[username]['expire_date'] = expire_date
                with open(USERS_DB, 'w') as f: json.dump(db, f)

def renew_key(username, add_gb, add_days):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                db[username]['total_gb'] = float(add_gb); db[username]['days'] = int(add_days)
                db[username]['expire_date'] = (datetime.now() + timedelta(days=int(add_days))).strftime("%Y-%m-%d")
                db[username]['used_bytes'] = 0; db[username]['last_raw_bytes'] = 0; db[username]['is_blocked'] = False; db[username]['is_online'] = False
                with open(USERS_DB, 'w') as f: json.dump(db, f)

def delete_key(username):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            if username in db:
                info = db[username]; ip = get_all_servers().get(info.get('node'), {}).get('ip')
                if ip:
                    cmd = get_safe_delete_cmd(username, info.get('protocol', 'v2'), info.get('port', '443'))
                    execute_ssh_bg(str(ip).strip(), [cmd, "systemctl restart xray"])
                del db[username]
                with open(USERS_DB, 'w') as f: json.dump(db, f)

def bulk_delete_keys(usernames):
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
            nodes = get_all_servers()
            cmds_by_ip = {}
            for uname in usernames:
                if uname in db:
                    ip = nodes.get(db[uname].get('node'), {}).get('ip')
                    if ip:
                        ip = str(ip).strip()
                        cmd = get_safe_delete_cmd(uname, db[uname].get('protocol', 'v2'), db[uname].get('port', '443'))
                        cmds_by_ip.setdefault(ip, []).append(cmd)
                    del db[uname]
            with open(USERS_DB, 'w') as f: json.dump(db, f)
            for ip, cmds in cmds_by_ip.items():
                cmds.append("systemctl restart xray")
                execute_ssh_bg(ip, cmds)

def rebalance_auto_node(group_id, new_limit, specific_node=None):
    groups = load_auto_groups()
    if group_id not in groups: return False, "Group not found"

    groups[group_id]["limit"] = new_limit
    for nid in groups[group_id]["nodes"]:
        if specific_node and nid != specific_node: continue
        if isinstance(groups[group_id]["nodes"][nid], dict): groups[group_id]["nodes"][nid]["limit"] = new_limit
        else: groups[group_id]["nodes"][nid] = {"ip": groups[group_id]["nodes"][nid], "limit": new_limit}
    save_auto_groups(groups)

    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)

        excess_users = []
        for nid, ndata in groups[group_id]["nodes"].items():
            if specific_node and nid != specific_node: continue
            users_on_node = [uname for uname, info in db.items() if info.get('node') == nid]
            if len(users_on_node) > new_limit:
                excess_users.extend(users_on_node[new_limit:])

        if not excess_users: return True, "Success"

        cmds_by_ip = {}
        migrated_count = 0
        
        for uname in excess_users:
            uinfo = db[uname]
            old_node = uinfo.get('node')
            old_ip = str(get_all_servers().get(old_node, {}).get('ip')).strip()
            old_port = uinfo.get('port')
            proto = uinfo.get('protocol')
            old_key_id = uinfo.get('key_id') 
            
            new_node_id, new_node_ip = find_available_node(group_id, 1, current_db=db)
            if not new_node_id: break
            
            new_node_ip = str(new_node_ip).strip()
            cmd_del = get_safe_delete_cmd(uname, proto, old_port)
            cmds_by_ip.setdefault(old_ip, []).append(cmd_del)
            
            used_ports = [int(i.get('port', 10000)) for i in db.values() if i.get('protocol') == 'out' and i.get('node') == new_node_id]
            new_port = str(max(used_ports) + 1) if used_ports else "10001"
            
            uid = uinfo.get('uuid')
            safe_u = urllib.parse.quote(uname)

            if proto == 'v2':
                new_port = "443"
                k = f"vless://{uid}@{new_node_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
                cmd_add = f"/usr/local/bin/v2ray-node-add-vless {uname} {uid}"
            else:
                raw_ss = f"chacha20-ietf-poly1305:{uid}@{new_node_ip}:{new_port}"
                ss_conf = base64.b64encode(raw_ss.encode('utf-8')).decode('utf-8').strip()
                k = f"ss://{ss_conf}#{safe_u}"
                cmd_add = f"/usr/local/bin/v2ray-node-add-out {uname} {uid} {new_port}"
                cmds_by_ip.setdefault(new_node_ip, []).append(f"ufw allow {new_port}/tcp && ufw allow {new_port}/udp")

            cmds_by_ip.setdefault(new_node_ip, []).append(cmd_add)
            
            db[uname]['node'] = new_node_id; db[uname]['port'] = new_port; db[uname]['key'] = k
            if old_key_id: db[uname]['key_id'] = old_key_id 
            
            migrated_count += 1
            
        with open(USERS_DB, 'w') as f: json.dump(db, f)

        for ip, cmds in cmds_by_ip.items():
            cmds.append("systemctl restart xray")
            execute_ssh_bg(ip, cmds)
            
        if migrated_count < len(excess_users):
            return False, f"Limit Updated. Migrated {migrated_count} keys. Failed to migrate {len(excess_users) - migrated_count} keys (No space)."
        return True, "Success"
