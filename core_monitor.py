import json
import os
import time
import subprocess
import base64
from datetime import datetime
from utils import get_all_servers, db_lock
from config import USERS_DB

def safe_remote_remove_keys(node_ip, emails_to_remove):
    """JSON မပျက်စေရန် အထူးကာကွယ်ထားသော Python ဖြင့် Key များကို ဖယ်ရှားမည်"""
    py_script = f"""
import json, os
try:
    with open('/usr/local/etc/xray/config.json', 'r') as f: cfg = json.load(f)
    changed = False
    emails = {json.dumps(emails_to_remove)}
    for inbound in cfg.get('inbounds', []):
        if 'settings' in inbound and 'clients' in inbound['settings']:
            original_len = len(inbound['settings']['clients'])
            inbound['settings']['clients'] = [c for c in inbound['settings']['clients'] if c.get('email') not in emails]
            if len(inbound['settings']['clients']) != original_len: changed = True
    if changed:
        with open('/usr/local/etc/xray/config.json', 'w') as f: json.dump(cfg, f, indent=4)
        os.system('systemctl restart xray')
except Exception as e: pass
"""
    encoded = base64.b64encode(py_script.encode('utf-8')).decode('utf-8')
    os.system(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{node_ip} \"echo {encoded} | base64 -d | python3\"")

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
    except:
        return {}

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
                except:
                    is_expired = False
                    
                is_over_limit = (total_gb > 0 and used_gb >= total_gb)
                
                if is_over_limit or is_expired:
                    if not uinfo.get('is_blocked', False):
                        uinfo['is_blocked'] = True
                        db_changed = True
                        
                        node_ip = nodes.get(uinfo.get('node'), {}).get('ip')
                        if node_ip:
                            if node_ip not in nodes_to_block: nodes_to_block[node_ip] = []
                            nodes_to_block[node_ip].append(uname)
                            
            if db_changed:
                with db_lock:
                    with open(USERS_DB, 'w') as f: json.dump(db, f)
                    
            # 🚀 Monitor မှ အုပ်စုလိုက် Block လုပ်ခြင်း (Safe Script)
            for ip, users in nodes_to_block.items():
                safe_remote_remove_keys(ip, users)
                    
        except Exception as e:
            print("Monitor Error:", e)
            
        time.sleep(60)

def start_background_monitor():
    import threading
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
