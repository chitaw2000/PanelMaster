import subprocess
import threading
import base64

# ---------------------------------------------------------
# 🚀 THE UNTOUCHABLE SSH ENGINE
# Command များကို Base64 ပြောင်း၍ Bash Script အဖြစ် သေချာပေါက် Run မည်
# ---------------------------------------------------------
def _ssh_task(ip, script_content):
    try:
        b64 = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')
        full_cmd = f"ssh -o ConnectTimeout=20 -o StrictHostKeyChecking=no root@{ip} \"echo {b64} | base64 -d > /tmp/pm_task.sh && bash /tmp/pm_task.sh\""
        subprocess.run(full_cmd, shell=True)
    except Exception:
        pass

def execute_ssh_bg(ip, cmds):
    if not cmds: 
        return
        
    if isinstance(cmds, list):
        # 🚀 Command များကြားတွင် 1 စက္ကန့် နားပေးခြင်းဖြင့် ဆာဗာ Overload ကို ကာကွယ်မည်
        script_content = "\nsleep 1\n".join(cmds)
    else:
        script_content = cmds
        
    threading.Thread(target=_ssh_task, args=(ip, script_content), daemon=True).start()

# ---------------------------------------------------------
# 🚀 VLESS (v2) အတွက် Python JSON Editor (Method B)
# Node ဆာဗာပေါ်တွင် Python ကို အသုံးပြု၍ JSON ဖိုင်ကို အမှားကင်းစွာ တည်းဖြတ်မည်
# ---------------------------------------------------------
def get_xray_json_remove_cmd(protocol, user_uuid, port):
    py_script = """
import json

config_file = '/usr/local/etc/xray/config.json'
TARGET_PROTOCOL = 'REPLACE_PROTOCOL'
TARGET_UUID = 'REPLACE_UUID'
TARGET_PORT = 'REPLACE_PORT'

try:
    with open(config_file, 'r') as f:
        data = json.load(f)
        
    changed = False
    
    if TARGET_PROTOCOL == 'v2':
        # Vless အတွက် UUID ကို ရှာ၍ ဖျက်မည်
        for inbound in data.get('inbounds', []):
            if inbound.get('protocol') == 'vless':
                clients = inbound.get('settings', dict()).get('clients', [])
                original_len = len(clients)
                
                new_clients = []
                for c in clients:
                    if str(c.get('id')) != TARGET_UUID:
                        new_clients.append(c)
                        
                inbound['settings']['clients'] = new_clients
                
                if len(new_clients) != original_len:
                    changed = True
                    
    else:
        # Shadowsocks အတွက် Port ကို ရှာ၍ ဖျက်မည်
        inbounds = data.get('inbounds', [])
        original_len = len(inbounds)
        
        new_inbounds = []
        for ib in inbounds:
            if str(ib.get('port')) != TARGET_PORT:
                new_inbounds.append(ib)
                
        data['inbounds'] = new_inbounds
        
        if len(new_inbounds) != original_len:
            changed = True

    if changed:
        with open(config_file, 'w') as f:
            json.dump(data, f, indent=4)
except Exception as e:
    pass
"""
    # Replace variables securely
    py_script = py_script.replace('REPLACE_PROTOCOL', str(protocol))
    py_script = py_script.replace('REPLACE_UUID', str(user_uuid))
    py_script = py_script.replace('REPLACE_PORT', str(port))
    
    b64_script = base64.b64encode(py_script.encode('utf-8')).decode('utf-8')
    return f"echo {b64_script} | base64 -d > /tmp/remove_xray.py && python3 /tmp/remove_xray.py"

# ---------------------------------------------------------
# 🚀 DYNAMIC ACTION COMMANDS (Block / Unblock / Delete)
# ---------------------------------------------------------
def get_block_cmd(username, protocol, port, user_uuid):
    if protocol == 'v2':
        # Vless အတွက် JSON ထဲမှ အပြီးဖယ်ထုတ်မည် (Method B)
        return get_xray_json_remove_cmd(protocol, user_uuid, port)
    else:
        # Shadowsocks အတွက် UFW Firewall ဖြင့် Port ကို ပိတ်မည် (Method C)
        return f"ufw insert 1 deny {port}/tcp >/dev/null 2>&1 || true\nufw insert 1 deny {port}/udp >/dev/null 2>&1 || true"

def get_unblock_cmd(username, protocol, port, user_uuid):
    if protocol == 'v2':
        # Vless အတွက် Script ဖြင့် ပြန်ထည့်မည် (Script အဟောင်းက ထည့်သည့်အခါ လုံးဝအလုပ်လုပ်ပါသည်)
        return f"/usr/local/bin/v2ray-node-add-vless {username} {user_uuid} >/dev/null 2>&1 || true"
    else:
        # Shadowsocks အတွက် UFW Block ကို ပြန်ဖွင့်ပေးမည် (Method C)
        return f"ufw delete deny {port}/tcp >/dev/null 2>&1 || true\nufw delete deny {port}/udp >/dev/null 2>&1 || true\nufw allow {port}/tcp >/dev/null 2>&1 || true\nufw allow {port}/udp >/dev/null 2>&1 || true"

def get_safe_delete_cmd(username, protocol, port, user_uuid):
    if protocol == 'v2':
        # Vless ကို အပြီးဖျက်ရန် JSON မှ ဖယ်ထုတ်မည်
        return get_xray_json_remove_cmd(protocol, user_uuid, port)
    else:
        # Shadowsocks ကို အပြီးဖျက်ရန် JSON မှ ဖယ်ထုတ်ပြီး UFW Rules များကိုပါ ရှင်းလင်းမည်
        remove_json = get_xray_json_remove_cmd(protocol, user_uuid, port)
        clear_ufw = f"ufw delete allow {port}/tcp >/dev/null 2>&1 || true\nufw delete allow {port}/udp >/dev/null 2>&1 || true\nufw delete deny {port}/tcp >/dev/null 2>&1 || true\nufw delete deny {port}/udp >/dev/null 2>&1 || true"
        return f"{remove_json}\n{clear_ufw}"
