import os, base64

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
    # 🚀 Xray Config မှ User ကို အတိအကျ တိုက်ရိုက် ဖျက်ထုတ်မည့် Python Script
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
    # 🚀 SSH မှတဆင့် လုံခြုံစွာပို့နိုင်ရန် Base64 ပြောင်းခြင်း
    b64_script = base64.b64encode(py_script.strip().encode()).decode()
    
    if protocol == 'v2':
        bash_cmd = f"/usr/local/bin/v2ray-node-del-vless {username} || true"
    else:
        bash_cmd = f"/usr/local/bin/v2ray-node-del-out {username} {port} || true ; ufw delete allow {port}/tcp || true ; ufw delete allow {port}/udp || true"
        
    # Script အဟောင်းကိုပါ တွဲ Run ပြီး၊ အသစ်နဲ့ပါ Config ကို ရှင်းထုတ်မည်
    return f"{bash_cmd} ; echo {b64_script} | base64 -d | python3"
