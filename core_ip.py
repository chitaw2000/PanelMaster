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
    """ဆာဗာပေါ်တွင် ချိတ်ဆက်ခဲ့သော IP များကို Xray Log မှ တိကျစွာ ရှာဖွေပြီး History တွင် သိမ်းမည်"""
    active_ips = set()
    try:
        # 🚀 THE FIX: Shadowsocks ကော VLESS ကော နှစ်ခုလုံးအတွက် History (Log) ကို ဖတ်မည်
        # Shadowsocks (out) ဆိုလျှင် Port နံပါတ်ဖြင့် ရှာမည်။ VLESS ဆိုလျှင် Username ဖြင့် ရှာမည်။
        search_term = str(port) if protocol == 'out' else username
        
        # Access Log နှင့် Journalctl နှစ်ခုလုံးမှ နောက်ဆုံး စာကြောင်း ၅၀၀၀ ကို ရှာဖွေမည်
        cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"cat /var/log/xray/access.log 2>/dev/null | tail -n 5000 | grep 'accepted' | grep '{search_term}' || journalctl -u xray --no-pager -n 5000 2>/dev/null | grep 'accepted' | grep '{search_term}'\""
        
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        for line in res.stdout.splitlines():
            # Xray Log ထဲမှ Client IP ကို Regex ဖြင့် တိကျစွာ ဆွဲထုတ်မည် (ဥပမာ - 1.2.3.4:56789 accepted)
            match = re.search(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):\d+\s+accepted', line)
            if match:
                active_ips.add(match.group(1))
                
        # 🚀 အပိုဆောင်း ကာကွယ်မှု: Live Connection (ss) ကိုပါ Shadowsocks အတွက် ထပ်စစ်ပေးမည်
        if protocol == 'out':
            cmd_ss = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"ss -tn state established | grep ':{port}'\""
            res_ss = subprocess.run(cmd_ss, shell=True, capture_output=True, text=True, timeout=5)
            for line in res_ss.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    peer_ip = parts[4].rsplit(':', 1)[0]
                    active_ips.add(peer_ip)

    except Exception as e:
        print(f"IP Fetch Error: {e}")
        pass
        
    # Local IP များနှင့် Private IP များကို ဖယ်ရှားမည်
    clean_ips = set()
    for ip in active_ips:
        if ip and ip != "127.0.0.1" and ip != node_ip and not ip.startswith("10.") and not ip.startswith("192.168."):
            clean_ips.add(ip)
            
    # 🚀 History DB တွင် အချိန်နှင့်တကွ မှတ်တမ်းတင်ခြင်း
    now_str = datetime.now().strftime("%Y-%m-%d %I:%M %p")
    sorted_history = []
    
    with db_lock:
        ips_db = {}
        if os.path.exists(IPS_DB):
            try:
                with open(IPS_DB, 'r') as f: ips_db = json.load(f)
            except: pass
            
        user_history = ips_db.get(username, [])
        history_dict = {entry['ip']: entry for entry in user_history}
        
        db_changed = False
        # အသစ်ဝင်လာသော IP များကို Update လုပ်မည်
        for ip in clean_ips:
            if ip not in history_dict:
                loc = fetch_geoip(ip)
                history_dict[ip] = {"ip": ip, "location": loc, "last_seen": now_str}
                db_changed = True
            else:
                history_dict[ip]["last_seen"] = now_str
                # Location Unknown ဖြစ်နေလျှင် ပြန်ရှာပေးမည်
                if history_dict[ip]["location"] == "Unknown Location" or not history_dict[ip]["location"]:
                    history_dict[ip]["location"] = fetch_geoip(ip)
                db_changed = True
                
        # နောက်ဆုံးဝင်ထားသော IP ၁၅ ခုကို အချိန်အလိုက် (အသစ်ဆုံးက အပေါ်) စီပြီး သိမ်းမည်
        sorted_history = sorted(history_dict.values(), key=lambda x: x.get('last_seen', ''), reverse=True)[:15] 
        
        if db_changed or (len(user_history) != len(sorted_history)):
            ips_db[username] = sorted_history
            with open(IPS_DB, 'w') as f: json.dump(ips_db, f)
            
    return sorted_history
