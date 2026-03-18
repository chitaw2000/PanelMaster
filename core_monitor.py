import time, json, subprocess, os, threading
from utils import get_all_servers, db_lock, get_safe_delete_cmd
USERS_DB = "/root/PanelMaster/users_db.json"

def start_background_monitor():
    def background_traffic_monitor():
        while True:
            time.sleep(30)
            try:
                nodes = get_all_servers()
                if not nodes: continue
                gathered_stats = {}
                for node_id, info in nodes.items():
                    node_ip = info.get('ip')
                    if not node_ip: continue
                    try:
                        cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"/usr/local/bin/xray api statsquery --server=127.0.0.1:10085\""
                        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                        user_bytes = {}
                        if res.stdout.strip():
                            stats = json.loads(res.stdout).get("stat", [])
                            for s in stats:
                                parts = s.get("name", "").split(">>>"); val = s.get("value", 0)
                                if len(parts) >= 4:
                                    if parts[0] == "user": user_bytes[parts[1]] = user_bytes.get(parts[1], 0) + val
                                    elif parts[0] == "inbound" and parts[1].startswith("out-"): user_bytes[parts[1][4:]] = user_bytes.get(parts[1][4:], 0) + val
                        gathered_stats[node_id] = user_bytes
                    except Exception: pass
                
                if not gathered_stats: continue
                db_changed = False
                users_to_block = []
                
                with db_lock:
                    if not os.path.exists(USERS_DB): continue
                    with open(USERS_DB, 'r') as f: db = json.load(f)
                    for uname, uinfo in db.items():
                        node_id = uinfo.get("node")
                        if node_id in gathered_stats:
                            user_bytes = gathered_stats[node_id]
                            val = user_bytes.get(uname, uinfo.get('last_raw_bytes', 0))
                            last_raw = uinfo.get('last_raw_bytes', 0)
                            
                            if val > last_raw: uinfo['is_online'] = True
                            else: uinfo['is_online'] = False
                            
                            if val < last_raw: uinfo['used_bytes'] = uinfo.get('used_bytes', 0) + val
                            else: uinfo['used_bytes'] = uinfo.get('used_bytes', 0) + (val - last_raw)
                            
                            uinfo['last_raw_bytes'] = val; db_changed = True
                            
                            tot_gb = float(uinfo.get('total_gb', 0))
                            if tot_gb > 0:
                                max_bytes = tot_gb * (1024**3)
                                if float(uinfo['used_bytes']) >= max_bytes and not uinfo.get('is_blocked', False):
                                    uinfo['is_blocked'] = True; uinfo['is_online'] = False
                                    node_ip = nodes[node_id].get('ip')
                                    if node_ip: users_to_block.append((node_ip, uname, uinfo.get('protocol', 'v2'), uinfo.get('port', '443')))
                    if db_changed:
                        with open(USERS_DB, 'w') as f: json.dump(db, f)
                        
                for node_ip, uname, proto, port in users_to_block:
                    safe_cmd = get_safe_delete_cmd(uname, proto, port)
                    subprocess.run(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{node_ip} \"{safe_cmd}\"", shell=True)
                    subprocess.run(f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{node_ip} \"systemctl restart xray\"", shell=True)
            except Exception: pass
    threading.Thread(target=background_traffic_monitor, daemon=True).start()
