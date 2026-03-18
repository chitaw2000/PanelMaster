import os, threading

try:
    from config import NODES_LIST
except ImportError:
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"

db_lock = threading.Lock()
AUTO_GROUPS_FILE = "/root/PanelMaster/auto_groups.json"

def get_nodes():
    nodes = {}
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                if '|' in line:
                    parts = line.split('|')
                    if len(parts) >= 3:
                        nodes[parts[0]] = {"name": parts[1], "ip": parts[2]}
                else:
                    parts = line.rsplit(' ', 1)
                    if len(parts) == 2:
                        nodes[parts[0]] = {"name": parts[0], "ip": parts[1]}
    return nodes

def get_all_servers():
    import json
    servers = get_nodes()
    if os.path.exists(AUTO_GROUPS_FILE):
        try:
            with open(AUTO_GROUPS_FILE, 'r') as f:
                groups = json.load(f)
                for gid, gdata in groups.items():
                    for nid, ndata in gdata.get("nodes", {}).items():
                        nip = ndata.get("ip") if isinstance(ndata, dict) else ndata
                        servers[nid] = {"name": f"[AUTO] {nid}", "ip": nip}
        except: pass
    return servers

def check_live_status(db):
    active = set()
    for uname, info in db.items():
        try:
            if info.get('is_online', False) and not info.get('is_blocked', False):
                active.add(uname)
        except: pass
    return active

def get_safe_delete_cmd(username, protocol, port):
    # 🚀 Xray မှ သေချာပေါက် ဖျက်ချပေးမည့် မူရင်း Script အဟောင်းကိုသာ ပြန်အသုံးပြုပါမည်
    if protocol == 'v2': 
        return f"/usr/local/bin/v2ray-node-del-vless {username}"
    else: 
        return f"/usr/local/bin/v2ray-node-del-out {username} {port}"
