import json, os, time, subprocess, threading
from datetime import datetime

from utils import get_all_servers, db_lock
from core_auto import load_auto_groups
from core_engine import get_safe_delete_cmd

try:
    from config import USERS_DB, NODES_LIST, load_config
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"

def get_target_ip(node_id):
    nodes = get_all_servers()
    if node_id in nodes and nodes[node_id].get('ip'):
        return str(nodes[node_id]['ip']).strip()
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                if line.startswith(f"{node_id}|") or line.startswith(f"{node_id} "):
                    parts = line.replace('|', ' ').split()
                    return parts[-1]
    return None

def fetch_xray_stats(ip):
    try:
        export_path = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; "
        cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{ip} '{export_path} xray api statsquery --server=127.0.0.1:10085'"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        # Error မရှိဘဲ Data ရလာမှသာ ပြန်ပို့ပေးမည် (Pending မဖြစ်စေရန်)
        if res.returncode == 0 and res.stdout:
            data = json.loads(res.stdout)
            return data.get("stat", [])
    except:
        pass
    return None

def suspend_user_everywhere(username, uinfo):
    port = uinfo.get('port')
    group_id = uinfo.get('group')
    target_node = uinfo.get('node')
    groups = load_auto_groups()
    g_nodes = groups.get(group_id, {}).get("nodes", {}) if group_id else {target_node: {}}
    
    for nid in g_nodes:
        nip = get_target_ip(nid)
        if not nip: continue
        export_path = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; "
        cmd_del = get_safe_delete_cmd(username, 'out', port)
        full_del = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{nip} '{export_path} {cmd_del} ; systemctl restart xray'"
        subprocess.Popen(full_del, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def monitor_traffic():
    while True:
        time.sleep(12)
        try:
            with db_lock:
                if not os.path.exists(USERS_DB): continue
                with open(USERS_DB, 'r') as f: db = json.load(f)

            if not db: continue

            # ၁။ User များ လက်ရှိ Active ဖြစ်နေသော ဆာဗာ IP ကိုသာ ယူမည်
            users_by_ip = {}
            for uname, uinfo in db.items():
                if not isinstance(uinfo, dict) or uinfo.get('is_blocked', False): continue
                nip = get_target_ip(uinfo.get('node'))
                if nip:
                    nip = str(nip).strip()
                    if nip not in users_by_ip: users_by_ip[nip] = []
                    users_by_ip[nip].append((uname, uinfo))

            db_changed = False
            current_date = datetime.now().strftime("%Y-%m-%d")

            # ၂။ ဆာဗာတစ်ခုချင်းစီဆီမှ Sequential (အသေအချာ စောင့်ပြီး) ဆွဲမည်
            for ip, user_list in users_by_ip.items():
                ip_stats = fetch_xray_stats(ip)
                if ip_stats is None:
                    continue # SSH ချိတ်မရလျှင် ကျော်သွားမည် (Pending မဖြစ်စေရန်)

                stat_dict = {}
                for s in ip_stats:
                    p = s.get("name", "").split(">>>")
                    if len(p) >= 4:
                        stat_dict[p[1]] = stat_dict.get(p[1], 0) + s.get("value", 0)

                for uname, uinfo in user_list:
                    current_val = stat_dict.get(uname, 0)
                    last_val = float(uinfo.get('last_raw_bytes', 0))

                    diff = 0
                    if current_val > last_val:
                        diff = current_val - last_val
                    elif current_val < last_val and current_val > 0:
                        diff = current_val # Xray Restart ကျသွားလျှင်

                    if diff > 0:
                        uinfo['used_bytes'] = float(uinfo.get('used_bytes', 0)) + diff
                        db_changed = True

                    if uinfo.get('last_raw_bytes') != current_val:
                        uinfo['last_raw_bytes'] = current_val
                        db_changed = True

                    # Limit စစ်ဆေးခြင်း
                    limit_bytes = float(uinfo.get('total_gb', 0)) * (1024**3)
                    if limit_bytes > 0 and float(uinfo.get('used_bytes', 0)) >= limit_bytes:
                        uinfo['is_blocked'] = True
                        db_changed = True
                        threading.Thread(target=suspend_user_everywhere, args=(uname, uinfo), daemon=True).start()

                    # Expire Date စစ်ဆေးခြင်း
                    exp = uinfo.get('expire_date')
                    if exp and current_date > exp:
                        uinfo['is_blocked'] = True
                        db_changed = True
                        threading.Thread(target=suspend_user_everywhere, args=(uname, uinfo), daemon=True).start()

            # ၃။ Database သိမ်းမည်
            if db_changed:
                with db_lock:
                    with open(USERS_DB, 'r') as f: current_db = json.load(f)
                    for uname, uinfo in db.items():
                        if uname in current_db:
                            current_db[uname].update(uinfo)
                    with open(USERS_DB, 'w') as f: json.dump(current_db, f, indent=4)
                    
        except Exception as e:
            print(f"Monitor error: {e}")

def start_background_monitor():
    t = threading.Thread(target=monitor_traffic, daemon=True)
    t.start()
