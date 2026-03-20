import json
import os
import time
import subprocess
from datetime import datetime
from utils import get_all_servers, db_lock
from config import USERS_DB

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
            nodes_to_restart = set()
            
            # ၁။ Node များဆီမှ Data Update လုပ်ခြင်း
            for nid, ninfo in nodes.items():
                nip = ninfo.get('ip')
                if not nip: continue
                
                stats = fetch_node_stats(nip)
                for uname, uinfo in db.items():
                    if uinfo.get('node') == nid and uname in stats:
                        uinfo['used_bytes'] = uinfo.get('used_bytes', 0) + stats[uname]
                        db_changed = True
                        
            # ၂။ Limit ပြည့်/မပြည့် စစ်ဆေး၍ အမှန်တကယ် Block လုပ်ခြင်း (The Bite!)
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
                            # 🚀 အစ်ကို၏ မူရင်း jq ဖြင့် Config ထဲမှ တကယ်ဖြတ်ထုတ်သော စနစ်
                            os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"jq '(.inbounds[] | select(.protocol==\\\"vless\\\" or .protocol==\\\"shadowsocks\\\").settings.clients) |= map(select(.email != \\\"{uname}\\\"))' /usr/local/etc/xray/config.json > /tmp/c.json && mv /tmp/c.json /usr/local/etc/xray/config.json\"")
                            nodes_to_restart.add(node_ip)
                            
            if db_changed:
                with db_lock:
                    with open(USERS_DB, 'w') as f: json.dump(db, f)
                    
            # Xray များကို Restart ချပေးခြင်း
            for ip in nodes_to_restart:
                os.system(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{ip} 'systemctl restart xray'")
                    
        except Exception as e:
            print("Monitor Error:", e)
            
        time.sleep(60) # တစ်မိနစ်တစ်ခါ စစ်ဆေးမည်

def start_background_monitor():
    import threading
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
