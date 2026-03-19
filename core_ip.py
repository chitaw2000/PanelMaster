import subprocess
import urllib.request
import json
import re
import os
from datetime import datetime
from utils import db_lock

IPS_DB = "/root/PanelMaster/ips_db.json"
IP_CACHE = {}

def fetch_geoip(ip):
    """IP မှ နိုင်ငံနှင့် မြို့ကို ရှာဖွေပေးမည့် Free API"""
    if ip in IP_CACHE: return IP_CACHE[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                city = data.get('city', '')
                country = data.get('country', '')
                isp = data.get('isp', '')
                loc = f"{city}, {country}" if city else country
                loc_str = f"{loc} ({isp})"
                IP_CACHE[ip] = loc_str
                return loc_str
    except:
        pass
    return "Unknown Location"

def get_active_ips(node_ip, port, protocol, username):
    """ဆာဗာပေါ်တွင် လက်ရှိချိတ်ဆက်နေသော IP များကို တိကျစွာ ရှာဖွေပြီး History တွင် သိမ်းမည်"""
    active_ips = set()
    try:
        if protocol == 'out': 
            # 🚀 Shadowsocks အတွက်
            cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"ss -tn state established | grep ':{port}'\""
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    peer_ip_port = parts[4]
                    ip = peer_ip_port.rsplit(':', 1)[0]
                    active_ips.add(ip)
        else: 
            # 🚀 VLESS အတွက် (Regex ဖြင့် တိကျစွာ ဆွဲထုတ်မည်)
            cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"cat /var/log/xray/access.log 2>/dev/null | tail -n 3000 | grep 'accepted' | grep '{username}'\""
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            for line in res.stdout.splitlines():
                # ဥပမာ - 1.2.3.4:56789 accepted tcp:...
                match = re.search(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):\d+\s+accepted', line)
                if match:
                    active_ips.add(match.group(1))
    except Exception as e:
        pass
        
    # Local IP များကို ဖယ်ရှားမည်
    clean_ips = set()
    for ip in active_ips:
        if ip and ip != "127.0.0.1" and ip != node_ip and not ip.startswith("10.") and not ip.startswith("192.168."):
            clean_ips.add(ip)
            
    # 🚀 History DB တွင် မှတ်တမ်းတင်ခြင်း
    now_str = datetime.now().strftime("%Y-%m-%d %I:%M %p")
    
    with db_lock:
        ips_db = {}
        if os.path.exists(IPS_DB):
            try:
                with open(IPS_DB, 'r') as f: ips_db = json.load(f)
            except: pass
            
        user_history = ips_db.get(username, [])
        history_dict = {entry['ip']: entry for entry in user_history}
        
        db_changed = False
        for ip in clean_ips:
            if ip not in history_dict:
                loc = fetch_geoip(ip)
                history_dict[ip] = {"ip": ip, "location": loc, "last_seen": now_str}
                db_changed = True
            else:
                history_dict[ip]["last_seen"] = now_str
                if history_dict[ip]["location"] == "Unknown Location" or not history_dict[ip]["location"]:
                    history_dict[ip]["location"] = fetch_geoip(ip)
                db_changed = True
                
        # နောက်ဆုံးဝင်ထားသော IP ၁၅ ခုကို အချိန်အလိုက်စီပြီး သိမ်းမည်
        sorted_history = sorted(history_dict.values(), key=lambda x: x['last_seen'], reverse=True)[:15] 
        ips_db[username] = sorted_history
        
        if db_changed:
            with open(IPS_DB, 'w') as f: json.dump(ips_db, f)
            
        return sorted_history
