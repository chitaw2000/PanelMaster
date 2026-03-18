import os

try:
    from config import NODES_LIST
except ImportError:
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"

def get_nodes():
    nodes = {}
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                parts = line.split()
                if len(parts) >= 3:
                    nodes[parts[0]] = {"name": " ".join(parts[1:-1]).replace("_", " "), "ip": parts[-1]}
                elif len(parts) == 2:
                    nodes[parts[0]] = {"name": parts[0], "ip": parts[1]}
    return nodes

def check_live_status(db):
    active = set()
    for uname, info in db.items():
        try:
            if info.get('is_online', False) and not info.get('is_blocked', False):
                active.add(uname)
        except: pass
    return active

def get_safe_delete_cmd(username, protocol, port):
    if protocol == 'v2': return f"/usr/local/bin/v2ray-node-del-vless {username}"
    else: return f"/usr/local/bin/v2ray-node-del-out {username} {port}"
