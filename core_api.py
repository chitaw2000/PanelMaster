from flask import Blueprint, request, jsonify
import json, os, urllib.parse, base64, uuid, random, string, subprocess
from datetime import datetime, timedelta

from utils import get_all_servers, db_lock
from core_auto import load_auto_groups
# 🚀 Manual လုပ်သကဲ့သို့ အသေအချာ အလုပ်လုပ်ရန် core_engine မှ ခေါ်သုံးသည်
from core_engine import get_safe_delete_cmd, execute_ssh_bg

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
        
    user_info = next((info for info in db.values() if isinstance(info, dict) and info.get('token') == token), None)
    if not user_info or user_info.get('is_blocked', False):
        return jsonify({"error": "Invalid token or key is blocked/expired"}), 403
        
    node_ip = get_target_ip(user_info.get('node'))
    if not node_ip: return jsonify({"error": "Target node offline"}), 500
    
    data = {
        "server": node_ip,
        "server_port": int(user_info.get('port', 10000)),
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
        group_list = [{"id": gid, "name": gdata.get("name", gid), "serverCount": len(gdata.get("nodes", {}))} for gid, gdata in groups.items()]
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

        api_keys_dict = {} 
        g_nodes = groups[group_id].get("nodes", {})
        
        # 🚀 ညိုကီပြောသည့်အတိုင်း Group ထဲရှိ Node "အားလုံး" ကို ချက်ချင်း Create လုပ်မည်
        for nid in g_nodes:
            nip = get_target_ip(nid)
            if not nip: continue
            nip = str(nip).strip()
            
            api_keys_dict[nid] = {
                "server": nip,
                "server_port": int(port),
                "password": str(uid),
                "method": "chacha20-ietf-poly1305",
                "prefix": "\u0016\u0003\u0001\u0005\u00f2\u0001\u0000\u0005\u00ee\u0003\u0003"
            }
            
            # မူလ execute_ssh_bg ကို သုံးထားသဖြင့် လုံးဝ သေချာပေါက် ပေါ်လာမည်
            cmd_add = f"/usr/local/bin/v2ray-node-add-out {username} {uid} {port} ; ufw allow {port}/tcp >/dev/null 2>&1 || true ; ufw allow {port}/udp >/dev/null 2>&1 || true ; systemctl restart xray"
            execute_ssh_bg(nip, [cmd_add])

        b64_creds_active = base64.urlsafe_b64encode(f"chacha20-ietf-poly1305:{uid}".encode('utf-8')).decode('utf-8').rstrip('=')
        active_key = f"ss://{b64_creds_active}@{target_ip.strip()}:{port}#{safe_u}"

        existing_ids = [int(u.get('key_id', 0)) for u in db.values() if isinstance(u, dict) and str(u.get('key_id', '')).isdigit()]
        next_id = max(existing_ids) + 1 if existing_ids else 1

        db[username] = {
            "node": target_node, "group": group_id, "protocol": "out", "uuid": uid,
            "port": port, "total_gb": total_gb, "expire_date": expire_date,
            "used_bytes": 0, "last_raw_bytes": 0, "is_blocked": False, "is_online": False,
            "key": active_key, "key_id": next_id, "token": token
        }

        with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)

    return jsonify({"success": True, "keys": api_keys_dict, "token": token})

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
            target_node = nid; break
            
    if not target_node: return jsonify({"success": False, "error": "Target node not found"}), 404

    new_ip = get_target_ip(target_node)
    if not new_ip: return jsonify({"success": False, "error": "Target node offline"}), 500
    new_ip = str(new_ip).strip()

    with db_lock:
        if not os.path.exists(USERS_DB): return jsonify({"success": False, "error": "DB not found"}), 404
        with open(USERS_DB, 'r') as f: db = json.load(f)
        
        username = next((uname for uname, info in db.items() if isinstance(info, dict) and info.get('token') == token), None)
        if not username: return jsonify({"success": False, "error": "Invalid token"}), 404
        uinfo = db[username]
        
        old_node = uinfo.get('node')
        if old_node == target_node: return jsonify({"success": True, "message": "Already connected"})
        
        old_ip = get_target_ip(old_node)
        old_ip = str(old_ip).strip() if old_ip else None
        
        uid = uinfo.get('uuid')
        port = uinfo.get('port')
        safe_u = urllib.parse.quote(username)
        group_id = uinfo.get('group')
        is_blocked = uinfo.get('is_blocked', False)
        
        # 🚀 ညိုကီ့ Logic: အဟောင်းက GB ကို ယူလာပြီး အသစ်မှာ ပေါင်းထည့်မည် (ရိုးရှင်းသော Subprocess ဖြင့်)
        if old_ip:
            try:
                cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{old_ip} 'xray api statsquery --server=127.0.0.1:10085'"
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if res.stdout:
                    stats = json.loads(res.stdout).get("stat", [])
                    for s in stats:
                        p = s.get("name", "").split(">>>")
                        if len(p) >= 4 and p[1] == username:
                            uinfo['used_bytes'] = float(uinfo.get('used_bytes', 0)) + float(s.get("value", 0))
            except: pass

        uinfo['last_raw_bytes'] = 0 
        b64_creds = base64.urlsafe_b64encode(f"chacha20-ietf-poly1305:{uid}".encode('utf-8')).decode('utf-8').rstrip('=')
        uinfo['node'] = target_node  
        uinfo['key'] = f"ss://{b64_creds}@{new_ip}:{port}#{safe_u}"
        
        with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)
        
    # 🚀 ညိုကီ့ Logic: ပြောင်းလိုက်သော အသစ်တွင် ဖွင့်၊ ကျန်သည့် Node အားလုံးတွင် အသေအချာ ပိတ်မည်
    if not is_blocked:
        groups = load_auto_groups()
        g_nodes = groups.get(group_id, {}).get("nodes", {}) if group
