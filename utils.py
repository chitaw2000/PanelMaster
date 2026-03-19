import os, threading, base64

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

# 🚀 THE FATAL BUG FIXED: အရင်က အလုပ်လုပ်ခဲ့သော Xray Config မှ တိုက်ရိုက် ဖြတ်ချမည့် Base64 Python Script ကို ပြန်လည်အသက်သွင်းလိုက်ပါပြီ!!
def get_safe_delete_cmd(username, protocol, port):
    py_script = f"""
import json
try:
    with open('/usr/local/etc/xray/config.json', 'r') as f: c = json.load(f)
    new_inbounds = []
    for inb in c.get('inbounds', []):
        if 'settings' in inb and 'clients' in inb['settings']:
            inb['settings']['clients'] = [cl for cl in inb['settings']['clients'] if str(cl.get('email', '')) != '{username}']
        if str(inb.get('port', '')) == '{port}' and str(inb.get('protocol', '')) == 'shadowsocks':
            continue
        new_inbounds.append(inb)
    c['inbounds'] = new_inbounds
    with open('/usr/local/etc/xray/config.json', 'w') as f: json.dump(c, f, indent=2)
except Exception: pass
"""
    b64_script = base64.b64encode(py_script.strip().encode()).decode().strip()
    
    if protocol == 'v2': 
        bash_cmd = f"/usr/local/bin/v2ray-node-del-vless '{username}' || true"
    else: 
        bash_cmd = f"/usr/local/bin/v2ray-node-del-out '{username}' {port} || true ; ufw delete allow {port}/tcp || true ; ufw delete allow {port}/udp || true"
        
    # 🚀 Config အား တိုက်ရိုက်ပြင်ဆင်မည့် Python Code အား Server ပေါ်တွင် Execute လုပ်မည်
    return f"{bash_cmd} ; echo {b64_script} | base64 -d | python3"
