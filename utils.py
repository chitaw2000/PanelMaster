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
                parts = line.strip().split()
                if len(parts) >= 3:
                    # Format အသစ်: ID, Name, IP
                    nodes[parts[0]] = {"name": parts[1], "ip": parts[2]}
                elif len(parts) == 2:
                    # Format အဟောင်း: Name, IP တွေ့လျှင် Name ကိုပဲ ID အဖြစ်သုံးမည်
                    nodes[parts[0]] = {"name": parts[0], "ip": parts[1]}
    return nodes

def check_live_status(db):
    active = set()
    for uname, info in db.items():
        try:
            # Data အဟောင်းများ String ဖြစ်နေပါက Error မတက်စေရန် float ပြောင်းစစ်မည်
            if float(info.get('used_bytes', 0)) > 0 and not info.get('is_blocked', False):
                active.add(uname)
        except:
            pass
    return active

def get_safe_delete_cmd(username, protocol, port):
    if protocol == 'v2':
        return f"/usr/local/bin/v2ray-node-del-vless {username}"
    else:
        return f"/usr/local/bin/v2ray-node-del-out {username} {port}"
