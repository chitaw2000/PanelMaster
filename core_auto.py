import json, os
from utils import db_lock, AUTO_GROUPS_FILE

try:
    from config import USERS_DB
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"

def load_auto_groups():
    if not os.path.exists(AUTO_GROUPS_FILE): return {}
    try:
        with open(AUTO_GROUPS_FILE, 'r') as f: return json.load(f)
    except: return {}

def save_auto_groups(data):
    with open(AUTO_GROUPS_FILE, 'w') as f: json.dump(data, f, indent=4)

def find_available_node(group_id, required_qty):
    groups = load_auto_groups()
    if group_id not in groups: return None, None
    
    group = groups[group_id]
    limit = int(group.get("limit", 30))
    nodes = group.get("nodes", {}) # {"auto_01": "1.1.1.1", "auto_02": "2.2.2.2"}
    
    if not nodes: return None, None

    # Database ထဲမှ လက်ရှိသုံးနေသော Key အရေအတွက်ကို ရေတွက်မည်
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
        else:
            db = {}

    counts = {nid: 0 for nid in nodes.keys()}
    for uname, uinfo in db.items():
        nid = uinfo.get("node")
        if nid in counts: counts[nid] += 1

    # 🚀 အစဉ်လိုက် (Sequential) နေရာလွတ်ရှာခြင်း
    # ဥပမာ auto_01 မှာ နေရာလွတ်ရင် အရင်ထည့်မည်၊ ပြည့်သွားမှ auto_02 သို့ဆက်သွားမည်
    for nid in sorted(nodes.keys()):
        if counts[nid] + required_qty <= limit:
            return nid, nodes[nid] # ပြည့်မနေသော Node ID နှင့် IP ကို ပြန်ပေးမည်

    return None, None # နေရာလွတ်မရှိပါ
