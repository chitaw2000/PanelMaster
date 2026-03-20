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
            
            # 🚀 THE FIX: Monitor က GB မတွက်တော့ပါ။ အစ်ကို့ Bot ကိုပဲ တွက်ခိုင်းပါမည်။ 
            # Monitor က Limit ပြည့်/မပြည့် စစ်ပြီး အမှန်တကယ် Block လုပ်ခြင်းကိုသာ တာဝန်ယူမည်။
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
                            if node_ip not in nodes_to_block: nodes_to_block[node_ip] = []
                            nodes_to_block[node_ip].append(uname)
                            
            if db_changed:
                with db_lock:
                    with open(USERS_DB, 'w') as f: json.dump(db, f)
                    
            # 🚀 Xray ထဲမှ အမှန်တကယ် ဖြတ်ချမည် (The Bite!)
            for ip, users in nodes_to_block.items():
                safe_remote_remove_keys(ip, users)
                    
        except Exception as e:
            print("Monitor Error:", e)
            
        time.sleep(60) # တစ်မိနစ်တစ်ခါ စစ်ဆေးမည်

def start_background_monitor():
    import threading
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
