import time
import json
import subprocess
import os
import threading
from utils import get_all_servers, db_lock, NODES_DB
from core_engine import execute_ssh_bg, get_safe_delete_cmd

try:
    from config import USERS_DB, NODES_LIST
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"

# ---------------------------------------------------------
# 🚀 IP အတိအကျ ရယူမည့် Helper 
# (IP မှား၍ Block Command မရောက်ခြင်းမှ ကာကွယ်ရန်)
# ---------------------------------------------------------
def get_robust_ip_monitor(node_id):
    nodes = get_all_servers()
    if node_id in nodes:
        node_info = nodes[node_id]
        if node_info.get('ip'):
            return str(node_info['ip']).strip()
    
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
# 🚀 BACKGROUND TRAFFIC MONITOR & AUTO-BLOCKER
# ---------------------------------------------------------
def background_traffic_monitor():
    while True:
        time.sleep(20)
        try:
            nodes = get_all_servers()
            if not nodes: 
                continue
            
            gathered_stats = {}
            for node_id, info in nodes.items():
                # 🚀 IP ကို သေချာစွာ ယူမည်
                node_ip = get_robust_ip_monitor(node_id)
                if not node_ip: 
                    continue
                    
                try:
                    cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"/usr/local/bin/xray api statsquery --server=127.0.0.1:10085\""
                    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    user_bytes = {}
                    
                    if res.stdout.strip():
                        stats = json.loads(res.stdout).get("stat", [])
                        for s in stats:
                            parts = s.get("name", "").split(">>>")
                            val = s.get("value", 0)
                            if len(parts) >= 4:
                                if parts[0] == "user": 
                                    user_bytes[parts[1]] = user_bytes.get(parts[1], 0) + val
                                elif parts[0] == "inbound" and parts[1].startswith("out-"): 
                                    user_bytes[parts[1][4:]] = user_bytes.get(parts[1][4:], 0) + val
                                    
                    gathered_stats[node_id] = user_bytes
                except: 
                    pass

            if not gathered_stats: 
                continue

            users_to_block_by_ip = {}
            
            with db_lock:
                if not os.path.exists(USERS_DB): 
                    continue
                with open(USERS_DB, 'r') as f: 
                    db = json.load(f)
                
                ndb = {}
                if os.path.exists(NODES_DB):
                    try:
                        with open(NODES_DB, 'r') as f: 
                            ndb = json.load(f)
                    except: 
                        pass
                
                db_changed = False
                ndb_changed = False
                
                for uname, uinfo in db.items():
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
                            
                        uinfo['used_bytes'] = uinfo.get('used_bytes', 0) + delta
                        uinfo['last_raw_bytes'] = val
                        db_changed = True
                        
                        if node_id not in ndb: 
                            ndb[node_id] = {"used_bytes": 0, "limit_tb": 0, "health": "green"}
                        
                        current_node_bytes = float(ndb[node_id].get("used_bytes", 0))
                        ndb[node_id]["used_bytes"] = current_node_bytes + delta
                        ndb_changed = True
                        
                        # ---------------------------------------------------------
                        # 🚀 GB ပြည့်ပါက သေချာပေါက် ပိတ်မည့် အပိုင်း
                        # ---------------------------------------------------------
                        tot_gb = float(uinfo.get('total_gb', 0))
                        if tot_gb > 0:
                            max_bytes = tot_gb * (1024**3)
                            
                            if float(uinfo['used_bytes']) >= max_bytes and not uinfo.get('is_blocked', False):
                                uinfo['is_blocked'] = True
                                uinfo['is_online'] = False
                                
                                # 🚀 IP အမှန်ကို သေချာစွာ ယူ၍ Block Command စုဆောင်းမည်
                                node_ip = get_robust_ip_monitor(node_id)
                                if node_ip:
                                    cmd_str = get_safe_delete_cmd(uname, uinfo.get('protocol', 'v2'), uinfo.get('port', '443'))
                                    if node_ip not in users_to_block_by_ip:
                                        users_to_block_by_ip[node_ip] = []
                                    users_to_block_by_ip[node_ip].append(cmd_str)
            
            if db_changed:
                with open(USERS_DB, 'w') as f: 
                    json.dump(db, f)
            if ndb_changed:
                with open(NODES_DB, 'w') as f: 
                    json.dump(ndb, f)

            # ---------------------------------------------------------
            # 🚀 စုထားသော Block Command များကို SSH သို့ လုံခြုံစွာ လှမ်းပို့မည်
            # ---------------------------------------------------------
            for node_ip, cmds in users_to_block_by_ip.items():
                cmds.append("systemctl reset-failed xray")
                cmds.append("systemctl restart xray")
                execute_ssh_bg(node_ip, cmds)
                
        except Exception as e: 
            pass

def start_background_monitor():
    threading.Thread(target=background_traffic_monitor, daemon=True).start()
