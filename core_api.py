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

# 🚀 SSH ကို သေချာပေါက် Run မည့်စနစ် (PATH နှင့် Quote ပြဿနာ ရှင်းပြီး)
def run_ssh_task(ip, cmd):
    try:
        export_path = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; "
        safe_cmd = cmd.replace("'", "'\\''")
        full_ssh = f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{ip} '{export_path} {safe_cmd}'"
        subprocess.run(full_ssh, shell=True)
    except Exception as e:
        print(f"SSH Error on {ip}: {e}")

# 🚀 အဟောင်းဖျက်၊ အသစ်ထည့် အလုပ်ကို အစဉ်လိုက် သေချာပေါက် လုပ်ပေးမည့် Thread
def switch_node_ssh_bg(old_ip, new_ip, username, proto, old_port, new_port, uid):
    # ၁။ အဟောင်းမှ ဖျက်မည်
    if old_ip:
        cmd_del = get_safe_delete_cmd(username, proto, old_port)
        run_ssh_task(old_ip, f"{cmd_del} ; systemctl restart xray")
        
    # Queue မထစ်စေရန် ၁ စက္ကန့် စောင့်မည်
    time.sleep(1)
    
    # ၂။ အသစ်သို့ ထည့်မည်
    if new_ip:
        if proto == 'v2':
            cmd_add = f"/usr/local/bin/v2ray-node-add-vless {username} {uid}"
        else:
            cmd_add = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {new_port} ; ufw allow {new_port}/tcp >/dev/null 2>&1 || true ; ufw allow {new_port}/udp >/dev/null 2>&1 || true"
        run_ssh_task(new_ip, f"{cmd_add} ; systemctl restart xray")

# ==========================================
# EXTERNAL API ROUTES
# ==========================================

@api_bp.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, x-api-key'
    return response

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

    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: db = {}
        else:
            db = {}

        if username in db:
            return jsonify({"success": False, "error": "User already exists"}), 400

        from core_auto import find_available_node
        target_node, _ = find_available_node(group_id, 1, current_db=db)
        if not target_node:
            return jsonify({"success": False, "error": "Limit Reached! No space available."}), 400

        target_ip = get_target_ip(target_node)
        if not target_ip:
            return jsonify({"success": False, "error": "Active Node offline!"}), 500
        target_ip = target_ip.strip()

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
        
        # Sub-Panel အတွက် Group ထဲက Node အားလုံးစာ Key တွေ ကြိုထုတ်ပေးမည်
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

        # 🚀 ဒါပေမယ့် တကယ့် VPS မှာတော့ 'Target Node' (၁) ခုတည်းကိုသာ Add မည်
        cmd_add = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {port} ; ufw allow {port}/tcp >/dev/null 2>&1 || true ; ufw allow {port}/udp >/dev/null 2>&1 || true ; systemctl restart xray"
        threading.Thread(target=run_ssh_task, args=(target_ip, cmd_add), daemon=True).start()

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
        
        old_ip = get_target_ip(old_node)
        old_ip = str(old_ip).strip() if old_ip else None
        
        proto = uinfo.get('protocol', 'v2')
        uid = uinfo.get('uuid')
        port = uinfo.get('port')
        safe_u = urllib.parse.quote(username)
        is_blocked = uinfo.get('is_blocked', False)
        
        if proto == 'v2':
            new_key = f"vless://{uid}@{new_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
        else:
            credentials = f"chacha20-ietf-poly1305:{uid}"
            b64_creds = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8').rstrip('=')
            new_key = f"ss://{b64_creds}@{new_ip}:{port}#{safe_u}"
            
        uinfo['node'] = target_node  
        uinfo['key'] = new_key
        
        with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)
        
    # 🚀 အဟောင်းကို ဖျက်၊ အသစ်ကို ထည့်သည့် အလုပ်ကို လုပ်မည်
    if not is_blocked:
        threading.Thread(target=switch_node_ssh_bg, args=(old_ip, new_ip, username, proto, port, port, uid), daemon=True).start()
    else:
        # Block ဖြစ်နေပါက အဟောင်းကို ဖျက်ရုံသာ ဖျက်မည်
        if old_ip:
            cmd_del = get_safe_delete_cmd(username, proto, port)
            threading.Thread(target=run_ssh_task, args=(old_ip, f"{cmd_del} ; systemctl restart xray"), daemon=True).start()
        
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

        target_node = uinfo.get('node')
        node_ip = get_target_ip(target_node)
        if node_ip: node_ip = str(node_ip).strip()
        proto = uinfo.get('protocol', 'v2')
        port = uinfo.get('port')
        uid = uinfo.get('uuid')

        # 🚀 User Action များကို 'Active' ဖြစ်နေသော ဆာဗာ (၁) ခုတည်းတွင်သာ လုပ်မည်
        if node_ip:
            if action == "suspend" or action == "delete":
                cmd_del = get_safe_delete_cmd(username, proto, port)
                threading.Thread(target=run_ssh_task, args=(node_ip, f"{cmd_del} ; systemctl restart xray"), daemon=True).start()

            elif action == "resume":
                if proto == 'v2':
                    cmd_add = f"/usr/local/bin/v2ray-node-add-vless {username} {uid} ; systemctl restart xray"
                else:
                    cmd_add = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {port} ; ufw allow {port}/tcp >/dev/null 2>&1 || true ; ufw allow {port}/udp >/dev/null 2>&1 || true ; systemctl restart xray"
                threading.Thread(target=run_ssh_task, args=(node_ip, cmd_add), daemon=True).start()

        if action == "suspend":
            uinfo['is_blocked'] = True
        elif action == "resume":
            uinfo['is_blocked'] = False
        elif action == "delete":
            del db[username]
        else:
            return jsonify({"success": False, "error": "Invalid action type"}), 400

        with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)

    return jsonify({"success": True, "message": f"User {action} applied successfully"})
