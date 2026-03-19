import subprocess
import urllib.request
import json
import re

def fetch_geoip(ip):
    """IP မှ နိုင်ငံနှင့် မြို့ကို ရှာဖွေပေးမည့် Free API"""
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
                return f"{loc} ({isp})"
    except:
        pass
    return "Unknown Location"

def get_active_ips(node_ip, port, protocol, username):
    """ဆာဗာပေါ်တွင် လက်ရှိချိတ်ဆက်နေသော IP များကို Python ဖြင့် တိကျစွာ ခွဲခြမ်းစိတ်ဖြာမည်"""
    ips = set()
    try:
        if protocol == 'out': 
            # 🚀 Shadowsocks အတွက် (Port ဖြင့် Raw Data ဆွဲယူ၍ Python ဖြင့် စစ်မည်)
            cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"ss -tnp state established\""
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            
            for line in res.stdout.splitlines():
                if f":{port}" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        # ss output format: ESTAB 0 0 LocalIP:LocalPort PeerIP:PeerPort
                        peer_ip = parts[4].rsplit(':', 1)[0]
                        ips.add(peer_ip)
        else: 
            # 🚀 VLESS အတွက် (Xray Log အားလုံးကို ဆွဲယူ၍ Python Regex ဖြင့် တိကျစွာရှာမည်)
            # Log file သို့မဟုတ် systemd journal နှစ်ခုလုံးမှ ရှာဖွေပေးမည်
            cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"cat /var/log/xray/access.log 2>/dev/null | tail -n 2000 || journalctl -u xray --no-pager -n 2000 2>/dev/null\""
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            
            for line in res.stdout.splitlines():
                # username ပါဝင်သော 'accepted' log လိုင်းများကိုသာ ရွေးမည်
                if 'accepted' in line and username in line:
                    # Regex ဖြင့် Client IP အစစ်အမှန်ကိုသာ ကွက်ပြီး ဆွဲထုတ်မည် (ဥပမာ - 1.2.3.4:56789 accepted)
                    match = re.search(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):\d+\s+accepted', line)
                    if match:
                        ips.add(match.group(1))
    except Exception as e:
        print(f"IP Fetch Error: {e}")
        pass
    
    # Private IP နှင့် Local IP များကို ဖယ်ရှားမည်
    clean_ips = []
    for ip in ips:
        if ip and not ip.startswith('127.') and not ip.startswith('10.') and not ip.startswith('192.168.'):
            clean_ips.append(ip)
    
    results = []
    # နောက်ဆုံး IP ၅ ခုကိုသာ Location ရှာပြီး ပြမည် (Loading မြန်စေရန်)
    for ip in clean_ips[-5:]: 
        loc = fetch_geoip(ip)
        results.append({"ip": ip, "location": loc})
        
    return results
