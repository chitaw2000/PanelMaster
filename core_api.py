from flask import Blueprint, request, jsonify
import json, os, urllib.parse, base64, uuid, random, string, subprocess, threading, time
from datetime import datetime, timedelta

from utils import get_all_servers, db_lock
from core_auto import load_auto_groups
from core_engine import get_safe_delete_cmd

try:
    from config import USERS_DB, NODES_LIST
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"

api_bp = Blueprint('api_bp', __name__)
MASTER_API_KEY = "My_Super_Secret_VPN_Key_2026"

def get_target_ip(node_id):
    nodes = get_all_servers()
    if node_id in nodes and nodes[node_id].get('ip'):
        return str(nodes[node_id]['ip']).strip()
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                if line.startswith(f"{node_id}|") or line.startswith(f"{node_id} "):
                    parts = line.replace('|', ' ').split()
                    return parts[-1]
    return None

def run_ssh_task(ip, cmd):
    try:
        export_path = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; "
        safe_cmd = cmd.replace("'", "'\\''")
        full_ssh = f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{ip} '{export_path} {safe_cmd}'"
        subprocess.run(full_ssh, shell=True)
    except Exception as e:
        print(f"SSH Error on {ip}: {e}")

# 🚀 CORS ပြဿနာများ မဖြစ်စေရန် ခွင့်ပြုပေးခြင်း
@api_bp.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, x-api-key'
    return response


# ==========================================
# EXTERNAL API ROUTES
# ==========================================

@api_bp.route('/conf/<token>.json', methods=['GET', 'OPTIONS'])
def api_get_ssconf(token):
    if request.method == 'OPTIONS': return jsonify({"success": True}), 200
    
    with db_lock:
        if not os.path.exists(USERS_DB): return jsonify({"error": "DB not found"}), 404
        with open(USERS_DB, 'r') as f: db = json.load(f)
        
    user_info = None
    for uname, uinfo in db.items():
        if isinstance(uinfo, dict) and uinfo.get('token') == token:
            user_info = uinfo
            break
            
    if not user_info or user_info.get('is_blocked', False):
        return jsonify({"error": "Invalid token or key is blocked/expired"}), 403
        
    node_ip = get_target_ip(user_info.get('node'))
    if not node_ip: return jsonify({"error": "Target node offline"}), 500
    
    data = {
        "server": node_ip,
        "server_port": int(user_info.get('port', 443)),
        "password": user_info.get('uuid'),
        "method": "chacha20-ietf-poly1305",
        "prefix": "\u0016\u0003\u0001\u0005\u00f2\u0001\u0000\u0005\u00ee\u0003\u0003"
    }
    return jsonify(data)

@api_bp.route('/api/active-groups', methods=['GET', 'OPTIONS'])
def api_get_active_groups():
    if request.method == 'OPTIONS': return jsonify({"success": True}), 200
    if request.headers.get('x-api-key') != MASTER_API_KEY:
        return jsonify({"success": False, "error": "Unauthorized Access"}), 401
    
    try:
        groups = load_auto_groups()
        group_list = []
        for gid, gdata in groups.items():
            group_list.append({
                "id": gid,
                "name": gdata.get("name", gid),
                "serverCount": len(gdata.get("nodes", {}))
            })
        return jsonify({"success": True, "groups": group_list})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@api_bp.route('/api/generate-keys', methods=['POST', 'OPTIONS'])
def api_generate_keys():
    if request.method == 'OPTIONS': return jsonify({"success": True}), 200
    if request.headers.get('x-api-key') != MASTER_API_KEY:
        return jsonify({"success": False, "error": "Unauthorized Access"}), 401

    # 🚀 JSON Header လွဲခဲ့လျှင်တောင် အတင်း ဖတ်ခိုင်းမည် (force=True)
    req_data = request.get_json(force=True, silent=True)
    if not req_data: return jsonify({"success": False, "error": "Invalid JSON"}), 400

    group_id = req_data.get('masterGroupId')
    raw_username = req_data.get('userName')
    try: total_gb = float(req_data.get('totalGB', 0))
    except: total_gb = 0.0
    expire_date = req_data.get('expireDate', (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"))
    
    if not group_id or not raw_username:
        return jsonify({"success": False, "error": "Missing masterGroupId or userName"}), 400

    username = str(raw_username).strip().replace(" ", "_")
    groups = load_auto_groups()
    
    if group_id not in groups:
        return jsonify({"success": False, "error": "Group not found"}), 404

    # 🚀 Deadlock (သော့ငြိခြင်း) မဖြစ်စေရန် Lock အပြင်ဘက်တွင် အရင်ရှာမည်
    from core_auto import find_available_node
    target_node, _ = find_available_node(group_id, 1)
    if not target_node:
        return jsonify({"success": False, "error": "Limit Reached! No space available."}), 400

    # 🚀 Database ထဲသို့ ရေးမည့်အပိုင်းကိုသာ သီးသန့် Lock ချမည်
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: db = {}
        else:
            db = {}

        if username in db:
            return jsonify({"success": False, "error": "User already exists"}), 400

        target_ip = get_target_ip(target_node)
        if not target_ip:
            return jsonify({"success": False, "error": "Active Node offline!"}), 500

        uid = str(uuid.uuid4()).strip()
        token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
        safe_u = urllib.parse.quote(username)

        max_p = 10000
        for uinfo in db.values():
            if isinstance(uinfo, dict) and uinfo.get('protocol') == 'out':
                try: p = int(uinfo.get('port', 10000))
                except: p = 10000
                if p > max_p: max_p = p
        port = str(max_p + 1)

        db_keys_dict = {}
        api_keys_dict = {} 
        g_nodes = groups[group_id].get("nodes", {})
        
        for nid in g_nodes:
            nip = get_target_ip(nid)
            if not nip: continue
            
            credentials = f"chacha20-ietf-poly1305:{uid}"
            b64_creds = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8').rstrip('=')
            
            db_keys_dict[nid] = f"ss://{b64_creds}@{nip}:{port}#{safe_u}"
            api_keys_dict[nid] = {
                "server": str(nip),
                "server_port": int(port),
                "password": str(uid),
                "method": "chacha20-ietf-poly1305",
                "prefix": "\u0016\u0003\u0001\u0005\u00f2\u0001\u0000\u0005\u00ee\u0003\u0003"
            }
            
            cmd_add = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {port} ; ufw allow {port}/tcp >/dev/null 2>&1 || true ; ufw allow {port}/udp >/dev/null 2>&1 || true ; systemctl restart xray"
            threading.Thread(target=run_ssh_task, args=(nip, cmd_add), daemon=True).start()

        active_key = db_keys_dict.get(target_node, "")
        existing_ids = [int(u.get('key_id', 0)) for u in db.values() if isinstance(u, dict) and str(u.get('key_id', '')).isdigit()]
        next_id = max(existing_ids) + 1 if existing_ids else 1

        db[username] = {
            "node": target_node, "group": group_id, "protocol": "out", "uuid": uid,
            "port": port, "total_gb": total_gb, "expire_date": expire_date,
            "used_bytes": 0, "last_raw_bytes": 0, "is_blocked": False, "is_online": False,
            "key": active_key, "key_id": next_id, "token": token
        }

        with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)

    return jsonify({
        "success": True,
        "keys": api_keys_dict,
        "token": token
    })


@api_bp.route('/api/webhook/switch', methods=['POST', 'OPTIONS'])
def webhook_switch():
    if request.method == 'OPTIONS': return jsonify({"success": True}), 200
    if request.headers.get('x-api-key') != MASTER_API_KEY:
        return jsonify({"success": False, "error": "Unauthorized Access"}), 401

    req_data = request.get_json(force=True, silent=True)
    if not req_data: return jsonify({"success": False, "error": "Invalid JSON"}), 400

    token = req_data.get('token')
    target_node_raw = str(req_data.get('activeServer', '')).strip()

    if not token or not target_node_raw: 
        return jsonify({"success": False, "error": "Missing token or activeServer"}), 400

    target_node = None
    nodes = get_all_servers()
    
    for nid, ndata in nodes.items():
        if nid == target_node_raw or str(ndata.get('name', '')).strip() == target_node_raw:
            target_node = nid
            break
            
    if not target_node:
        if os.path.exists(NODES_LIST):
            with open(NODES_LIST, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    parts = line.split('|') if '|' in line else line.split()
                    if len(parts) >= 3:
                        if parts[0] == target_node_raw or parts[1] == target_node_raw:
                            target_node = parts[0]
                            break
                            
    if not target_node:
        return jsonify({"success": False, "error": f"Target node '{target_node_raw}' not found"}), 404

    new_ip = get_target_ip(target_node)
    if not new_ip:
        return jsonify({"success": False, "error": "Target node offline or invalid IP"}), 500
    new_ip = str(new_ip).strip()

    with db_lock:
        if not os.path.exists(USERS_DB): return jsonify({"success": False, "error": "DB not found"}), 404
        with open(USERS_DB, 'r') as f: db = json.load(f)
        
        username = None
        uinfo = None
        for uname, info in db.items():
            if isinstance(info, dict) and info.get('token') == token:
                username = uname
                uinfo = info
                break
                
        if not username: return jsonify({"success": False, "error": "Invalid token"}), 404
        
        old_node = uinfo.get('node')
        if old_node == target_node:
            return jsonify({"success": True, "message": f"Already connected to {target_node}"})
        
        proto = uinfo.get('protocol', 'v2')
        uid = uinfo.get('uuid')
        port = uinfo.get('port')
        safe_u = urllib.parse.quote(username)
        
        if proto == 'v2':
            new_key = f"vless://{uid}@{new_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
        else:
            credentials = f"chacha20-ietf-poly1305:{uid}"
            b64_creds = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8').rstrip('=')
            new_key = f"ss://{b64_creds}@{new_ip}:{port}#{safe_u}"
            
        uinfo['node'] = target_node  
        uinfo['key'] = new_key
        
        with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)
        
    return jsonify({"success": True, "message": f"Successfully switched to {target_node}"})


@api_bp.route('/api/user-action', methods=['POST', 'OPTIONS'])
def api_user_action():
    if request.method == 'OPTIONS': return jsonify({"success": True}), 200
    if request.headers.get('x-api-key') != MASTER_API_KEY:
        return jsonify({"success": False, "error": "Unauthorized Access"}), 401

    req_data = request.get_json(force=True, silent=True)
    if not req_data: return jsonify({"success": False, "error": "Invalid JSON"}), 400

    token = req_data.get('token')
    action = req_data.get('action')

    if not token or not action: 
        return jsonify({"success": False, "error": "Missing token or action"}), 400

    with db_lock:
        if not os.path.exists(USERS_DB): return jsonify({"success": False, "error": "DB not found"}), 404
        with open(USERS_DB, 'r') as f: db = json.load(f)
        
        username = None
        uinfo = None
        for uname, info in db.items():
            if isinstance(info, dict) and info.get('token') == token:
                username = uname
                uinfo = info
                break
                
        if not username: return jsonify({"success": False, "error": "Invalid token"}), 404

        group_id = uinfo.get('group')
        proto = uinfo.get('protocol', 'v2')
        port = uinfo.get('port')
        uid = uinfo.get('uuid')
        
        groups = load_auto_groups()
        g_nodes = groups.get(group_id, {}).get("nodes", {}) if group_id else {uinfo.get('node'): {}}

        for nid in g_nodes:
            nip = get_target_ip(nid)
            if not nip: continue

            prefix = "systemctl() { true; }; export -f systemctl; "
            suffix = " ; unset -f systemctl; systemctl restart xray"

            if action == "suspend" or action == "delete":
                cmd_del = get_safe_delete_cmd(username, proto, port)
                full_del = f"{cmd_del} ; systemctl restart xray" if proto == 'v2' else f"{prefix}{cmd_del}{suffix}"
                threading.Thread(target=run_ssh_task, args=(nip, full_del), daemon=True).start()

            elif action == "resume":
                if proto == 'v2':
                    cmd_add = f"/usr/local/bin/v2ray-node-add-vless {username} {uid} ; systemctl restart xray"
                else:
                    cmd_add = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {port} ; ufw allow {port}/tcp >/dev/null 2>&1 || true ; ufw allow {port}/udp >/dev/null 2>&1 || true ; systemctl restart xray"
                threading.Thread(target=run_ssh_task, args=(nip, cmd_add), daemon=True).start()

        if action == "suspend":
            uinfo['is_blocked'] = True
        elif action == "resume":
            uinfo['is_blocked'] = False
        elif action == "delete":
            del db[username]
        else:
            return jsonify({"success": False, "error": "Invalid action type"}), 400

        with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)

    return jsonify({"success": True, "message": f"User {action} applied to all nodes successfully"})
