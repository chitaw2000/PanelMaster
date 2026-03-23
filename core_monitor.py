import time, json, subprocess, os, threading, requests
from datetime import datetime
from utils import get_all_servers, db_lock, NODES_DB
from core_engine import execute_ssh_bg, get_safe_delete_cmd

try:
    from config import USERS_DB
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"

# 🚀 Sub-Panel သို့ GB Update လှမ်းပို့မည့် API Function
def send_gb_webhook(token, used_gb):
    if not token: return
    try:
        requests.post(
            "http://167.172.91.222:4000/api/internal/update-gb-api",
            json={"token": token, "usedGB": round(used_gb, 3)},
            headers={"Content-Type": "application/json", "x-api-key": "My_Super_Secret_VPN_Key_2026"},
            timeout=5
        )
    except: pass

def background_traffic_monitor():
    while True:
        time.sleep(20)
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
                            parts = s.get("name", "").split(">>>")
                            val = s.get("value", 0)
                            if len(parts) >= 4:
                                if parts[0] == "user": user_bytes[parts[1]] = user_bytes.get(parts[1], 0) + val
                                elif parts[0] == "inbound" and parts[1].startswith("out-"): user_bytes[parts[1][4:]] = user_bytes.get(parts[1][4:], 0) + val
                    gathered_stats[node_id] = user_bytes
                except: pass

            users_to_block_by_ip = {}
            with db_lock:
                if not os.path.exists(USERS_DB): continue
                with open(USERS_DB, 'r') as f: db = json.load(f)
                
                ndb = {}
                if os.path.exists(NODES_DB):
                    try:
                        with open(NODES_DB, 'r') as f: ndb = json.load(f)
                    except: pass
                
                db_changed = False
                current_date_str = datetime.now().strftime("%Y-%m-%d")
                
                for uname, uinfo in db.items():
                    if not isinstance(uinfo, dict): continue
                    node_id = uinfo.get("node")
                    
                    if node_id in gathered_stats:
                        user_bytes = gathered_stats[node_id]
                        val = user_bytes.get(uname, uinfo.get('last_raw_bytes', 0))
                        delta = val - uinfo.get('last_raw_bytes', 0) if val >= uinfo.get('last_raw_bytes', 0) else val
                        
                        uinfo['is_online'] = (val > uinfo.get('last_raw_bytes', 0))
                        uinfo['used_bytes'] = float(uinfo.get('used_bytes', 0)) + delta
                        uinfo['last_raw_bytes'] = val
                        db_changed = True
                        
                        if node_id not in ndb: ndb[node_id] = {"used_bytes": 0, "limit_tb": 0}
                        ndb[node_id]["used_bytes"] = float(ndb[node_id].get("used_bytes", 0)) + delta

                        # 🚀 Traffic တက်လာပါက Sub-Panel သို့ ချက်ချင်း လှမ်းပို့မည် (Background Thread ဖြင့်)
                        if delta > 0 and uinfo.get('token'):
                            threading.Thread(target=send_gb_webhook, args=(uinfo.get('token'), uinfo['used_bytes'] / (1024**3)), daemon=True).start()

                    is_expired = (uinfo.get('expire_date') and current_date_str > uinfo.get('expire_date'))
                    tot_gb = float(uinfo.get('total_gb', 0))
                    is_gb_full = (tot_gb > 0 and float(uinfo.get('used_bytes', 0)) >= (tot_gb * 1024**3))

                    if (is_expired or is_gb_full) and not uinfo.get('is_blocked', False):
                        uinfo['is_blocked'] = True
                        uinfo['is_online'] = False
                        db_changed = True
                        node_ip = nodes.get(node_id, {}).get('ip')
                        if node_ip:
                            cmd_str = get_safe_delete_cmd(uname, uinfo.get('protocol', 'v2'), uinfo.get('port', '443'))
                            users_to_block_by_ip.setdefault(node_ip, []).append((cmd_str, uinfo.get('protocol', 'v2')))
                
                if db_changed:
                    with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)
                    if ndb:
                        with open(NODES_DB, 'w') as f: json.dump(ndb, f, indent=4)

            # ဆာဗာမှ ပိတ်ခြင်း
            for ip, cmds_list in users_to_block_by_ip.items():
                vless_cmds = [c[0] for c in cmds_list if c[1] == 'v2']
                ss_cmds = [c[0] for c in cmds_list if c[1] != 'v2']
                
                if vless_cmds:
                    vless_cmds.append("systemctl restart xray")
                    execute_ssh_bg(ip, vless_cmds)
                if ss_cmds:
                    prefix = "systemctl() { true; }; export -f systemctl; "
                    suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
                    execute_ssh_bg(ip, [prefix + " ; ".join(ss_cmds) + suffix])
        except: pass

def start_background_monitor():
    threading.Thread(target=background_traffic_monitor, daemon=True).start()
