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
                        nodes[parts[0].strip()] = {"name": parts[1].strip(), "ip": parts[2].strip()}
                else:
                    parts = line.rsplit(' ', 1)
                    if len(parts) == 2:
                        nodes[parts[0].strip()] = {"name": parts[0].strip(), "ip": parts[1].strip()}
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
                        nip = str(ndata.get("ip")).strip() if isinstance(ndata, dict) else str(ndata).strip()
                        servers[nid.strip()] = {"name": f"[AUTO] {nid}", "ip": nip}
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

# 🚀 SSH Hang ဖြစ်စေသော || true များကိုဖြုတ်ကာ Custom Node ၏ မူလ Script အဟောင်းအတိုင်း အတိအကျပြန်ထားသည်
def get_safe_delete_cmd(username, protocol, port):
    if protocol == 'v2':
        return f"/usr/local/bin/v2ray-node-del-vless {username}"
    else:
        return f"/usr/local/bin/v2ray-node-del-out {username} {port}"
