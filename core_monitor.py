import time
import json
import subprocess
import os
import threading
from datetime import datetime
from utils import get_all_servers, db_lock, NODES_DB
from core_engine import execute_ssh_bg, get_block_cmd

try:
    from config import USERS_DB, NODES_LIST
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"

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

def background_traffic_monitor():
    while True:
        time.sleep(30)
        try:
            nodes = get_all_servers()
            if not nodes: 
                continue
            
            gathered_stats = {}
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
                    except Exception: 
                        pass
                
                db_changed = False
                ndb_changed = False
                
                for uname, uinfo in db.items():
                    if not isinstance(uinfo, dict): 
                        continue
                        
                    node_id = uinfo.get("node")
                    
                    if node_id in gathered_stats:
                        user_bytes = gathered_stats[node_id]
                        val = user_bytes.get(uname, uinfo.get('last_raw_bytes', 0))
                        last_raw = uinfo.get('last_raw_bytes', 0)
                        
                        delta = val - last_raw if val >= last_raw else val
                        
                        # 🚀 မသုံးဘဲ စိမ်းနေသည့် ပြဿနာရှင်းရန် (5KB ထက်ကျော်မှသာ Online ဟုသတ်မှတ်မည်)
                        if delta > 5000: 
                            uinfo['is_online'] = True
                        else: 
                            uinfo['is_online'] = False
                            
                        if delta > 0:
                            uinfo['used_bytes'] = float(uinfo.get('used_bytes', 0)) + delta
                            uinfo['last_raw_bytes'] = val
                            db_changed = True
                            
                            if node_id not in ndb: 
                                ndb[node_id] = {"used_bytes": 0, "limit_tb": 0, "health": "green"}
                            ndb[node_id]["used_bytes"] = float(ndb[node_id].get("used_bytes", 0)) + delta
                            ndb_changed = True

                    # 🚀 Expire သို့မဟုတ် GB ပြည့်ခြင်း စစ်ဆေးမည်
                    is_expired = False
                    exp_str = uinfo.get('expire_date')
                    if exp_str:
                        try:
                            exp_date = datetime.strptime(exp_str, "%Y-%m-%d")
                            if datetime.now() > exp_date:
                                is_expired = True
                        except Exception:
                            pass

                    is_gb_full = False
                    tot_gb = float(uinfo.get('total_gb', 0))
                    if tot_gb > 0:
                        max_bytes = tot_gb * (1024**3)
                        if float(uinfo.get('used_bytes', 0)) >= max_bytes:
                            is_gb_full = True

                    if (is_expired or is_gb_full) and not uinfo.get('is_blocked', False):
                        uinfo['is_blocked'] = True
                        uinfo['is_online'] = False
                        db_changed = True
                        
                        node_ip = get_robust_ip_monitor(node_id)
                        if node_ip:
                            protocol = uinfo.get('protocol', 'v2')
                            port = uinfo.get('port', '443')
                            cmd_str = get_block_cmd(uname, protocol, port)
                            
                            if node_ip not in users_to_block_by_ip:
                                users_to_block_by_ip[node_ip] = []
                            users_to_block_by_ip[node_ip].append(cmd_str)
                
                if db_changed:
                    with open(USERS_DB, 'w') as f: 
                        json.dump(db, f, indent=4)
                if ndb_changed:
                    with open(NODES_DB, 'w') as f: 
                        json.dump(ndb, f, indent=4)

            for node_ip, cmds in users_to_block_by_ip.items():
                cmds.append("systemctl restart xray")
                execute_ssh_bg(node_ip, cmds)
                
        except Exception: 
            pass

def start_background_monitor():
    threading.Thread(target=background_traffic_monitor, daemon=True).start()
