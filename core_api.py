import json, os
from utils import db_lock, get_all_servers

try:
    from config import USERS_DB, NODES_LIST
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"

def get_robust_ip(node_id):
    nodes = get_all_servers()
    if node_id in nodes and nodes[node_id].get('ip'):
        return str(nodes[node_id]['ip']).strip()
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f:
            for line in f:
                line = line.strip()
                if line and (line.startswith(f"{node_id}|") or line.startswith(f"{node_id} ")):
                    return line.replace('|', ' ').split()[-1]
    return None

def get_ssconf_data(token):
    with db_lock:
        if not os.path.exists(USERS_DB):
            return None
        try:
            with open(USERS_DB, 'r') as f:
                db = json.load(f)
        except:
            return None
            
    user_info = None
    for uname, uinfo in db.items():
        if isinstance(uinfo, dict) and uinfo.get('token') == token:
            user_info = uinfo
            break
            
    if not user_info:
        return None
        
    # Blocked သို့မဟုတ် Expired ဖြစ်နေလျှင် ချိတ်မရအောင် None ပြန်ပို့မည်
    if user_info.get('is_blocked', False):
        return None
        
    node_id = user_info.get('node')
    node_ip = get_robust_ip(node_id)
    
    if not node_ip:
        return None
        
    # 🚀 User အလိုရှိသော Custom API Format အတိအကျ
    data = {
        "server": node_ip,
        "server_port": int(user_info.get('port', 443)),
        "password": user_info.get('uuid'),
        "method": "chacha20-ietf-poly1305",
        "prefix": "\u0016\u0003\u0001\u0005\u00f2\u0001\u0000\u0005\u00ee\u0003\u0003"
    }
    return data
