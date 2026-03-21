import time
import json
import subprocess
import os
import threading

# Panel နှင့် Database Lock မျှသုံးရန် utils ကို ခေါ်ပါသည်
from utils import get_all_servers, db_lock, NODES_DB
# 🚀 မူလအလုပ်လုပ်နေသော Engine မှ Safe Command များကိုသာ ယူသုံးမည်
from core_engine import execute_ssh_bg, get_safe_delete_cmd

try:
    from config import USERS_DB, NODES_LIST
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"

# ---------------------------------------------------------
# 🚀 IP အမှန်ကို ရှာဖွေပေးမည့် Helper
# ---------------------------------------------------------
def get_robust_ip_monitor(node_id):
    nodes = get_all_servers()
    if node_id in nodes:
        info = nodes[node_id]
        if info.get('ip'):
            return str(info['ip']).strip()
            
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: 
                    continue
                if line.startswith(str(node_id) + "|") or line.startswith(str(node_id) + " "):
                    parts = line.replace('|', ' ').split()
                    return parts[-1].strip()
    return None

# ---------------------------------------------------------
# 🚀 သီးသန့်အလုပ်လုပ်မည့် နောက်ကွယ်က Auto-Blocker
# ---------------------------------------------------------
def background_traffic_monitor():
    while True:
        # စနစ် Overload မဖြစ်စေရန် စက္ကန့် ၃၀ တစ်ခါသာ အလုပ်လုပ်မည်
        time.sleep(30)
        
        try:
            nodes = get_all_servers()
            if not nodes:
                continue

            gathered_stats = {}
            # ၁။ Node များဆီမှ Traffic စာရင်း သွားတောင်းမည်
            for node_id, info in nodes.items():
                node_ip = get_robust_ip_monitor(node_id)
                if not node_ip:
                    continue
                    
                try:
                    cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"/usr/local/bin/xray api statsquery --server=127.0.0.1:10085\""
                    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    user_bytes = {}
                    
                    if res.stdout and str(res.stdout).strip():
                        stats = json.loads(res.stdout).get("stat", [])
                        for s in stats:
                            parts = s.get("name", "").split(">>>")
                            val = s.get("value", 0)
                            
                            if len(parts) >= 4:
                                if parts[0] == "user":
                                    user_bytes[parts[1]] = user_bytes.get(parts[1], 0) + val
                                elif parts[0] == "inbound" and parts[1].startswith("out-"):
                                    port_num = parts[1][4:]
                                    user_bytes[port_num] = user_bytes.get(port_num, 0) + val
                                    
                    gathered_stats[node_id] = user_bytes
                except Exception:
                    pass

            if len(gathered_stats) == 0:
                continue

            users_to_block_by_ip = {}

            # ၂။ Database ကို ဖွင့်၍ Traffic ပေါင်းထည့်မည် (Lock ဖြင့် သေချာကာကွယ်ထားသည်)
            with db_lock:
                if not os.path.exists(USERS_DB):
                    continue
                    
                with open(USERS_DB, 'r') as f:
                    db = json.load(f)
                    
                db_changed = False
                
                for uname, uinfo in db.items():
                    if not isinstance(uinfo, dict):
                        continue
                        
                    node_id = uinfo.get("node")
                    if node_id in gathered_stats:
                        user_bytes = gathered_stats[node_id]
                        
                        val = user_bytes.get(uname, uinfo.get('last_raw_bytes', 0))
                        last_raw = uinfo.get('last_raw_bytes', 0)
                        
                        if val >= last_raw:
                            delta = val - last_raw
                        else:
                            delta = val
                        
                        if val > last_raw:
                            uinfo['is_online'] = True
                        else:
                            uinfo['is_online'] = False
                        
                        if delta > 0:
                            current_used = float(uinfo.get('used_bytes', 0))
                            uinfo['used_bytes'] = current_used + delta
                            uinfo['last_raw_bytes'] = val
                            db_changed = True
                            
                        # ၃။ GB ပြည့်မပြည့် စစ်ဆေး၍ ပြည့်ပါက Block စာရင်းသွင်းမည်
                        tot_gb = float(uinfo.get('total_gb', 0))
                        if tot_gb > 0:
                            max_bytes = tot_gb * (1024**3)
                            current_used_bytes = float(uinfo.get('used_bytes', 0))
                            is_blocked_status = uinfo.get('is_blocked', False)
                            
                            if current_used_bytes >= max_bytes and is_blocked_status == False:
                                uinfo['is_blocked'] = True
                                uinfo['is_online'] = False
                                db_changed = True
                                
                                node_ip = get_robust_ip_monitor(node_id)
                                if node_ip:
                                    protocol = uinfo.get('protocol', 'v2')
                                    port = uinfo.get('port', '443')
                                    
                                    # 🚀 မူလအလုပ်လုပ်သော Safe Delete Command ဖြင့်သာ ပိတ်မည်
                                    cmd_str = get_safe_delete_cmd(uname, protocol, port)
                                    
                                    if node_ip not in users_to_block_by_ip:
                                        users_to_block_by_ip[node_ip] = []
                                    users_to_block_by_ip[node_ip].append(cmd_str)
                                    
                if db_changed:
                    with open(USERS_DB, 'w') as f:
                        json.dump(db, f, indent=4)
                        
            # ၄။ Block စာရင်းဝင်နေသော User များကို လှမ်းပိတ်မည်
            for node_ip, cmds in users_to_block_by_ip.items():
                cmds.append("systemctl restart xray")
                execute_ssh_bg(node_ip, cmds)
                
        except Exception:
            pass

def start_background_monitor():
    threading.Thread(target=background_traffic_monitor, daemon=True).start()
