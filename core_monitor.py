import json, os, time, subprocess, threading
from datetime import datetime

from utils import get_all_servers, db_lock
from core_auto import load_auto_groups
from core_engine import get_safe_delete_cmd, execute_ssh_bg

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
        cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{ip} \"/usr/local/bin/xray api statsquery --server=127.0.0.1:10085\""
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        data = json.loads(res.stdout)
        return data.get("stat", [])
    except:
        return []

def suspend_user_everywhere(username, uinfo):
    proto = uinfo.get('protocol', 'v2')
    port = uinfo.get('port')
    group_id = uinfo.get('group')
    target_node = uinfo.get('node')
    
    groups = load_auto_groups()
    g_nodes = groups.get(group_id, {}).get("nodes", {}) if group_id else {target_node: {}}
    
    for nid in g_nodes:
        nip = get_target_ip(nid)
        if not nip: continue
        
        if proto == 'v2':
            cmd_del = f"/usr/local/bin/v2ray-node-delete-vless {username}"
            full_del = f"{cmd_del} ; systemctl restart xray"
        else:
            cmd_del = f"/usr/local/bin/v2ray-node-delete-out {username} {port}"
            full_del = f"systemctl() {{ true; }}; export -f systemctl; {cmd_del} ; ufw delete allow {port}/tcp >/dev/null 2>&1 || true ; ufw delete allow {port}/udp >/dev/null 2>&1 || true ; unset -f systemctl; systemctl restart xray"
        
        subprocess.Popen(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{nip} '{full_del}'", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def monitor_traffic():
    while True:
        try:
            config = load_config()
            interval = config.get('interval', 12)
        except:
            interval = 12

        time.sleep(interval)

        with db_lock:
            if not os.path.exists(USERS_DB): continue
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: db = {}

        if not db: continue

        # 🚀 (၁) User များရှိနေသော ဆာဗာ IP အားလုံးကို အရင် ရှာဖွေစုစည်းမည်
        active_ips = set()
        groups = load_auto_groups()
        
        for uname, uinfo in db.items():
            if not isinstance(uinfo, dict) or uinfo.get('is_blocked', False): continue
            
            group_id = uinfo.get('group')
            target_node = uinfo.get('node')
            
            g_nodes = groups.get(group_id, {}).get("nodes", {}) if group_id else {target_node: {}}
            for nid in g_nodes:
                nip = get_target_ip(nid)
                if nip: active_ips.add(str(nip).strip())

        # 🚀 (၂) ဆာဗာအားလုံးဆီမှ Xray GB Stats များကို ပြိုင်တူ (Parallel) လှမ်းဆွဲမည်
        stats_by_ip = {}
        def _fetch(ip):
            stats_by_ip[ip] = fetch_xray_stats(ip)
        
        threads = []
        for ip in active_ips:
            t = threading.Thread(target=_fetch, args=(ip,))
            t.start()
            threads.append(t)
        
        for t in threads: t.join()

        # 🚀 (၃) User အလိုက် ဘယ်ဆာဗာကနေပဲ သုံးသုံး GB များကို လိုက်ပေါင်းပေးမည်
        db_changed = False
        current_date = datetime.now().strftime("%Y-%m-%d")

        for uname, uinfo in db.items():
            if not isinstance(uinfo, dict): continue
            if uinfo.get('is_blocked', False): continue

            group_id = uinfo.get('group')
            target_node = uinfo.get('node')
            g_nodes = groups.get(group_id, {}).get("nodes", {}) if group_id else {target_node: {}}
            
            # Multi-Node သုံးရန် IP အလိုက် Meter မှတ်မည့် Dictionary ဖန်တီးခြင်း
            if 'last_raw_bytes_dict' not in uinfo or not isinstance(uinfo['last_raw_bytes_dict'], dict):
                uinfo['last_raw_bytes_dict'] = {}
                
            total_new_traffic = 0
            
            for nid in g_nodes:
                nip = get_target_ip(nid)
                if not nip: continue
                nip = str(nip).strip()
                
                ip_stats = stats_by_ip.get(nip, [])
                user_bytes_on_this_ip = 0
                
                for s in ip_stats:
                    p = s.get("name", "").split(">>>")
                    if len(p) >= 4 and p[1] == uname:
                        user_bytes_on_this_ip += s.get("value", 0)
                        
                last_val = uinfo['last_raw_bytes_dict'].get(nip, 0)
                
                if user_bytes_on_this_ip > last_val:
                    diff = user_bytes_on_this_ip - last_val
                    total_new_traffic += diff
                elif user_bytes_on_this_ip < last_val:
                    # ဆာဗာတွင် Xray Restart ကျသွား၍ Meter သုည ပြန်ဖြစ်သွားပါက
                    total_new_traffic += user_bytes_on_this_ip
                    
                # နောက်တစ်ခေါက် တွက်ရန်အတွက် IP အလိုက် Meter ကို အသစ်ပြန်မှတ်မည်
                uinfo['last_raw_bytes_dict'][nip] = user_bytes_on_this_ip

            if total_new_traffic > 0:
                uinfo['used_bytes'] = float(uinfo.get('used_bytes', 0)) + total_new_traffic
                db_changed = True

            # 🚀 GB Limit ကျော်/မကျော် စစ်ဆေးခြင်း
            limit_bytes = float(uinfo.get('total_gb', 0)) * (1024**3)
            if limit_bytes > 0 and float(uinfo.get('used_bytes', 0)) >= limit_bytes:
                uinfo['is_blocked'] = True
                db_changed = True
                threading.Thread(target=suspend_user_everywhere, args=(uname, uinfo), daemon=True).start()

            # 🚀 Expire Date ကျော်/မကျော် စစ်ဆေးခြင်း
            exp = uinfo.get('expire_date')
            if exp and current_date > exp:
                uinfo['is_blocked'] = True
                db_changed = True
                threading.Thread(target=suspend_user_everywhere, args=(uname, uinfo), daemon=True).start()

        if db_changed:
            with db_lock:
                try:
                    with open(USERS_DB, 'r') as f: current_db = json.load(f)
                except: current_db = {}
                
                for u, i in db.items():
                    if u in current_db:
                        current_db[u].update(i)
                
                with open(USERS_DB, 'w') as f:
                    json.dump(current_db, f, indent=4)

def start_background_monitor():
    t = threading.Thread(target=monitor_traffic, daemon=True)
    t.start()
