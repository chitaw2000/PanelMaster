import subprocess
import urllib.request
import json

def fetch_geoip(ip):
    """IP မှ နိုင်ငံနှင့် မြို့ကို ရှာဖွေပေးမည့် Free API"""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return f"{data.get('city', '')}, {data.get('country', '')} ({data.get('isp', '')})"
    except:
        pass
    return "Unknown Location"

def get_active_ips(node_ip, port, protocol, username):
    """ဆာဗာပေါ်တွင် လက်ရှိချိတ်ဆက်နေသော IP များကို တိုက်ရိုက်ဆွဲထုတ်မည်"""
    ips = set()
    try:
        if protocol == 'out': 
            # Outline / Shadowsocks အတွက် (Port ဖြင့် အတိအကျ စစ်ဆေးမည်)
            cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"ss -tn state established \\'( dport = :{port} )\\' | awk 'NR>1 {{print \\$5}}' | cut -d: -f1\""
        else: 
            # VLESS အတွက် (Access Log မှတဆင့် စစ်ဆေးမည်)
            cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"tail -n 1000 /var/log/xray/access.log | grep 'accepted.*{username}' | awk '{{print \\$3}}' | cut -d: -f1\""
        
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        for line in res.stdout.strip().split('\n'):
            ip = line.strip()
            # IPv4 ကိုသာ ရွေးထုတ်မည်
            if ip and ip != "127.0.0.1" and ":" not in ip: 
                ips.add(ip)
    except Exception:
        pass
    
    results = []
    # နောက်ဆုံးချိတ်ထားသော IP ၅ ခုကိုသာ ပြမည်
    for ip in list(ips)[:5]: 
        loc = fetch_geoip(ip)
        results.append({"ip": ip, "location": loc})
        
    return results
