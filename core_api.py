from flask import Blueprint, request, jsonify
import json, os, urllib.parse, base64, uuid, random, string, subprocess
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

# 🚀 SSH ကို တိုက်ရိုက် စောင့်ပြီး Run မည့် Function (Thread မသုံးတော့ပါ)
def run_ssh_sync(ip, cmd):
    try:
        export_path = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; "
        safe_cmd = cmd.replace("'", "'\\''")
        full_ssh = f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{ip} '{export_path} {safe_cmd}'"
        subprocess.run(full_ssh, shell=True)
    except Exception as e:
        print(f"SSH Sync Error on {ip}: {e}")

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

    from core_auto import find_available_node
    
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: db = {}
        else:
            db = {}

        if username in db:
            return jsonify({"success": False, "error": "User already exists"}), 400

        target_node, _ = find_available_node(group_id, 1, current_db=db)
        if not target_node:
            return jsonify({"success": False, "error": "Limit Reached! No space available."}), 400

        target_ip = get_target_ip(target_node)
        if not target_ip:
            return jsonify({"success": False, "error": "Active Node offline!"}), 500

        uid = str(uuid.uuid4()).strip()
        token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
        safe_u = urllib.parse.quote(username)

        # Port ယူမည့်စနစ်
        max_p = 10000
        for uinfo in db.values():
            if isinstance(uinfo, dict) and uinfo.get('protocol') == 'out':
                try: p = int(uinfo.get('port', 10000))
                except: p = 10000
                if p > max_p: max_p = p
        port = str(max_p + 1)

        api_keys_dict = {} 
        g_nodes = groups[group_id].get("nodes", {})
        
        # 🚀 ၁။ ဆာဗာအားလုံးဆီသို့ Add ပြီး ပြန်ပိတ်မည့် အစီအစဉ် (Initialization)
        for nid in g_nodes:
            nip = get_target_ip(nid)
            if not nip: continue
            nip = str(nip).strip()
            
            credentials = f"chacha20-ietf-poly1305:{uid}"
            b64_creds = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8').rstrip('=')
            
            api_keys_dict[nid] = {
                "server": nip,
                "server_port": int(port),
                "password": str(uid),
                "method": "chacha20-ietf-poly1305",
                "prefix": "\u0016\u0003\u0001\u0005\u00f2\u0001\u0000\u0005\u00ee\u0003\u0003"
            }
            
            # Initial Creation on ALL nodes
            cmd_add = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {port} ; ufw allow {port}/tcp >/dev/null 2>&1 || true ; ufw allow {port}/udp >/dev/null 2>&1 || true"
            run_ssh_sync(nip, f"{cmd_add} ; systemctl restart xray")
            
            # သတ်မှတ်ထားသော Target Node မဟုတ်ပါက ချက်ချင်းပြန်ပိတ် (Delete) ထားမည်
            if nid != target_node:
                cmd_del = get_safe_delete_cmd(username, 'out', port)
                run_ssh_sync(nip, f"systemctl() {{ true; }}; export -f systemctl; {cmd_del} ; unset -f systemctl; systemctl restart xray")

        active_key = f"ss://{b64_creds}@{target_ip.strip()}:{port}#{safe_u}"

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
        
        # 🚀 (၁) အဟောင်း ဆာဗာမှ နောက်ဆုံး သုံးခဲ့သော GB ကို လှမ်းယူပြီး DB တွင် ပေါင်းထည့်မည်
        if old_ip:
            try:
                res = subprocess.run(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{old_ip} \"/usr/local/bin/xray api statsquery --server=127.0.0.1:10085\"", shell=True, capture_output=True, text=True)
                stats = json.loads(res.stdout).get("stat", [])
                for s in stats:
                    p = s.get("name", "").split(">>>")
                    v = s.get("value", 0)
                    if len(p) >= 4 and p[1] == username:
                        uinfo['used_bytes'] = float(uinfo.get('used_bytes', 0)) + v
            except Exception as e:
                print(f"GB Sync Error from old node: {e}")

        # Monitor အသစ်အတွက် Zero မှ ပြန်စတွက်ရန် Reset ချမည်
        uinfo['last_raw_bytes'] = 0
        
        # 🚀 (၂) ဆာဗာအသစ်သို့ ဖွင့်ပေးမည် (Synchronous)
        if proto == 'v2':
            cmd_add = f"/usr/local/bin/v2ray-node-add-vless {username} {uid}"
            run_ssh_sync(new_ip, f"{cmd_add} ; systemctl restart xray")
            new_key = f"vless://{uid}@{new_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
        else:
            cmd_add = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {port} ; ufw allow {port}/tcp >/dev/null 2>&1 || true ; ufw allow {port}/udp >/dev/null 2>&1 || true"
            run_ssh_sync(new_ip, f"{cmd_add} ; systemctl restart xray")
            credentials = f"chacha20-ietf-poly1305:{uid}"
            b64_creds = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8').rstrip('=')
            new_key = f"ss://{b64_creds}@{new_ip}:{port}#{safe_u}"
            
        # 🚀 (၃) ဆာဗာအဟောင်းမှ ပိတ် (ဖျက်) မည် (Synchronous)
        if old_ip and old_ip != new_ip:
            cmd_del = get_safe_delete_cmd(username, proto, port)
            if proto == 'v2':
                run_ssh_sync(old_ip, f"{cmd_del} ; systemctl restart xray")
            else:
                run_ssh_sync(old_ip, f"systemctl() {{ true; }}; export -f systemctl; {cmd_del} ; unset -f systemctl; systemctl restart xray")
                
        # 🚀 (၄) DB သို့ အပြီးသတ် သိမ်းမည်
        uinfo['node'] = target_node  
        uinfo['key'] = new_key
        with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)
        
    return jsonify({"success": True, "message": f"Successfully switched to {target_node} and synced GB"})


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

        if node_ip:
            if action == "suspend" or action == "delete":
                cmd_del = get_safe_delete_cmd(username, proto, port)
                full_del = f"{cmd_del} ; systemctl restart xray" if proto == 'v2' else f"systemctl() {{ true; }}; export -f systemctl; {cmd_del} ; unset -f systemctl; systemctl restart xray"
                run_ssh_sync(node_ip, full_del)

            elif action == "resume":
                if proto == 'v2':
                    cmd_add = f"/usr/local/bin/v2ray-node-add-vless {username} {uid}"
                    run_ssh_sync(node_ip, f"{cmd_add} ; systemctl restart xray")
                else:
                    cmd_add = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {port} ; ufw allow {port}/tcp >/dev/null 2>&1 || true ; ufw allow {port}/udp >/dev/null 2>&1 || true"
                    run_ssh_sync(node_ip, f"{cmd_add} ; systemctl restart xray")

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
