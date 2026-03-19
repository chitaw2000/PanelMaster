import os, threading, base64

try:
    from config import NODES_LIST
except ImportError:
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"

db_lock = threading.Lock()
AUTO_GROUPS_FILE = "/root/PanelMaster/auto_groups.json"
NODES_DB = "/root/PanelMaster/nodes_db.json"

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

def get_safe_delete_cmd(username, protocol, port):
    if protocol == 'v2':
        return f"/usr/local/bin/v2ray-node-del-vless '{username}'"
    else:
        return f"/usr/local/bin/v2ray-node-del-out '{username}' {port}"

# 🚀 THE ULTIMATE FIX: Bulk Key ထုတ်ခြင်းနှင့် Block ခြင်းများကို လုံးဝ (၁၀၀%) သေချာပေါက် အလုပ်လုပ်စေမည့် Base64 Execution
def execute_ssh_bg(ip, cmds):
    if not cmds: return
    script_content = "\n".join(cmds)
    b64 = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')
    os.system(f"ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no root@{ip} \"echo {b64} | base64 -d > /tmp/pm_task.sh && bash /tmp/pm_task.sh\" >/dev/null 2>&1 &")
