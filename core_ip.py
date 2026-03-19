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
            # 🚀 Shadowsocks အတွက် Port ဖြင့် စစ်ဆေးမည်
            cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"ss -tn state established | grep ':{port}'\""
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            for line in res.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 5:
                    # format: ESTAB 0 0 LocalIP:Port PeerIP:Port
                    ip_port = parts[4] 
                    ip = ip_port.rsplit(':', 1)[0] # IP ကိုသီးသန့် ဖြတ်ထုတ်သည်
                    if ip and ip != "127.0.0.1" and ip != node_ip: 
                        ips.add(ip)
        else: 
            # 🚀 VLESS အတွက် Access Log ဖြင့် စစ်ဆေးမည်
            cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"tail -n 1000 /var/log/xray/access.log | grep 'accepted' | grep '{username}'\""
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            for line in res.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 3:
                    # format: 2026/03/19 12:00:00 1.2.3.4:56789 accepted tcp:...
                    ip_port = parts[2]
                    if ip_port.startswith("tcp:") or ip_port.startswith("udp:"):
                        ip_port = ip_port.split(":", 1)[1]
                    ip = ip_port.rsplit(':', 1)[0] # IP ကိုသီးသန့် ဖြတ်ထုတ်သည်
                    if ip and ip != "127.0.0.1" and ip != node_ip: 
                        ips.add(ip)
    except Exception as e:
        pass
    
    results = []
    # နောက်ဆုံးချိတ်ထားသော IP ၅ ခုကိုသာ ပြမည်
    for ip in list(ips)[:5]: 
        loc = fetch_geoip(ip)
        results.append({"ip": ip, "location": loc})
        
    return results
