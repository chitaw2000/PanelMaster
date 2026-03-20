import json
import os
import time
import subprocess
import base64
from datetime import datetime
from utils import get_all_servers, db_lock
from config import USERS_DB

def get_safe_delete_cmd_multi(users_to_delete):
    py_script = f"""
import json
try:
    users_to_delete = {json.dumps(users_to_delete)}
    path = '/usr/local/etc/xray/config.json'
    with open(path, 'r') as f: d = json.load(f)
    changed = False
    new_inbounds = []
    
    out_ports = [str(u['port']) for u in users_to_delete if u['proto'] == 'out']
    v2_unames = [u['uname'] for u in users_to_delete if u['proto'] == 'v2']
    
    for ib in d.get('inbounds', []):
        if str(ib.get('port')) in out_ports and ib.get('protocol') == 'shadowsocks':
            changed = True
            continue
            
        if ib.get('protocol') == 'vless' and 'settings' in ib and 'clients' in ib['settings']:
            orig_len = len(ib['settings']['clients'])
            ib['settings']['clients'] = [c for c in ib['settings']['clients'] if c.get('email') not in v2_unames]
            if len(ib['settings']['clients']) != orig_len: changed = True
            
        new_inbounds.append(ib)
        
    if changed:
        d['inbounds'] = new_inbounds
        with open(path, 'w') as f: json.dump(d, f, indent=2)
except Exception as e: pass
"""
    b64_script = base64.b64encode(py_script.encode('utf-8')).decode()
    return f"echo {b64_script} | base64 -d | python3"

def fetch_node_stats(node_ip):
    try:
        cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"/usr/local/bin/xray api statsquery --server=127.0.0.1:10085\""
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        stats = json.loads(res.stdout).get("stat", [])
        data = {}
        for s in stats:
            p = s.get("name", "").split(">>>")
            v = s.get("value", 0)
            if len(p) >= 4 and p[0] == "user": 
                data[p[1]] = data.get(p[1], 0) + v
        return data
    except: return {}

def monitor_loop():
    while True:
        try:
            nodes = get_all_servers()
            with db_lock:
                if not os.path.exists(USERS_DB):
                    time.sleep(60)
                    continue
                with open(USERS_DB, 'r') as f: db = json.load(f)
                
            db_changed = False
            nodes_to_block = {}
            
            for nid, ninfo in nodes.items():
                nip = ninfo.get('ip')
                if not nip: continue
                
                stats = fetch_node_stats(nip)
                for uname, uinfo in db.items():
                    if uinfo.get('node') == nid and uname in stats:
                        uinfo['used_bytes'] = uinfo.get('used_bytes', 0) + stats[uname]
                        db_changed = True
                        
            now = datetime.now().date()
            for uname, uinfo in db.items():
                used_gb = float(uinfo.get('used_bytes', 0)) / (1024**3)
                total_gb = float(uinfo.get('total_gb', 0))
                try:
                    exp_date = datetime.strptime(uinfo.get('expire_date', '2099-01-01'), "%Y-%m-%d").date()
                    is_expired = now > exp_date
                except: is_expired = False
                    
                is_over_limit = (total_gb > 0 and used_gb >= total_gb)
                
                if is_over_limit or is_expired:
                    if not uinfo.get('is_blocked', False):
                        uinfo['is_blocked'] = True
                        db_changed = True
                        
                        node_ip = nodes.get(uinfo.get('node'), {}).get('ip')
                        if node_ip:
                            if node_ip not in nodes_to_block: nodes_to_block[node_ip] = []
                            # 🚀 Grouping users to safely block them all at once!
                            nodes_to_block[node_ip].append({'uname': uname, 'proto': uinfo.get('protocol', 'v2'), 'port': uinfo.get('port', '443')})
                            
            if db_changed:
                with db_lock:
                    with open(USERS_DB, 'w') as f: json.dump(db, f)
                    
            # 🚀 Node တစ်ခုစီအတွက် Safe Script ကို တစ်ကြိမ်တည်း Run ပြီး အားလုံးကို Block မည်
            for ip, users in nodes_to_block.items():
                safe_cmd = get_safe_delete_cmd_multi(users)
                os.system(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{ip} \"{safe_cmd} ; systemctl restart xray\"")
                    
        except Exception as e: print("Monitor Error:", e)
        time.sleep(60)

def start_background_monitor():
    import threading
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
