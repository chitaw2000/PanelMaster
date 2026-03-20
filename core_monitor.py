import json
import os
import time
import subprocess
import base64
from datetime import datetime
from utils import get_all_servers, db_lock
from config import USERS_DB

def remote_block_key(node_ip, protocol, username):
    """Node ဆီသို့ လှမ်း၍ Xray Config ထဲမှ User အား အပြီးတိုင် ဖြတ်ချမည်"""
    target_proto = "vless" if protocol == "v2" else "shadowsocks"
    py_script = f"""
import json, os
try:
    with open('/usr/local/etc/xray/config.json', 'r') as f: cfg = json.load(f)
    changed = False
    for inbound in cfg.get('inbounds', []):
        if inbound.get('protocol') == '{target_proto}':
            settings = inbound.get('settings', {{}})
            clients = settings.get('clients', [])
            original = len(clients)
            # အဆိုပါ Username အား Config ထဲမှ ဖယ်ရှားမည်
            settings['clients'] = [c for c in clients if c.get('email') != '{username}']
            inbound['settings'] = settings
            if len(settings['clients']) != original: changed = True
    if changed:
        with open('/usr/local/etc/xray/config.json', 'w') as f: json.dump(cfg, f, indent=4)
        os.system('systemctl restart xray')
except Exception as e: pass
"""
    # 🚀 SSH Quoting Error မတက်စေရန် Base64 ဖြင့် ပြောင်း၍ လှမ်းပို့မည်
    encoded = base64.b64encode(py_script.encode('utf-8')).decode('utf-8')
    subprocess.run(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"echo {encoded} | base64 -d | python3\"", shell=True, capture_output=True)

def fetch_node_stats(node_ip):
    """Node ဆီမှ အသုံးပြုထားသော Data များကို ဆွဲယူမည်"""
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
            
            # ၁။ Node များဆီမှ Data Update လုပ်ခြင်း
            for nid, ninfo in nodes.items():
                nip = ninfo.get('ip')
                if not nip: continue
                
                stats = fetch_node_stats(nip)
                for uname, uinfo in db.items():
                    if uinfo.get('node') == nid and uname in stats:
                        uinfo['used_bytes'] = uinfo.get('used_bytes', 0) + stats[uname]
                        db_changed = True
                        
            # ၂။ Limit ပြည့်/မပြည့် စစ်ဆေး၍ အမှန်တကယ် Block လုပ်ခြင်း
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
                        # DB တွင် Blocked ဟု သတ်မှတ်မည်
                        uinfo['is_blocked'] = True
                        db_changed = True
                        node_ip = nodes.get(uinfo.get('node'), {}).get('ip')
                        if node_ip:
                            # 🚀 ဆာဗာပေါ်မှ တကယ် ဖြတ်ချမည် (The Bite!)
                            remote_block_key(node_ip, uinfo.get('protocol', 'v2'), uname)
                            
            if db_changed:
                with db_lock:
                    with open(USERS_DB, 'w') as f: json.dump(db, f)
                    
        except Exception as e:
            print("Monitor Error:", e)
            
        time.sleep(60) # တစ်မိနစ်တစ်ခါ စစ်ဆေးမည်

def start_background_monitor():
    import threading
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
