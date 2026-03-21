import subprocess
import threading

# ---------------------------------------------------------
# 🚀 THE UNTOUCHABLE SSH ENGINE
# Command များကို File အဖြစ်မရေးဘဲ SSH Bash သို့ တိုက်ရိုက် Stream လုပ်၍ Run မည်
# ---------------------------------------------------------
def _ssh_task(ip, script_content):
    try:
        # stdin=subprocess.PIPE ဖြင့် ပို့ခြင်းသည် Base64 ပြဿနာများကို လုံးဝ (၁၀၀%) ကျော်လွှားနိုင်ပါသည်
        proc = subprocess.Popen(
            f"ssh -o ConnectTimeout=20 -o StrictHostKeyChecking=no root@{ip} 'bash -s'",
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        proc.communicate(input=script_content.encode('utf-8'))
    except Exception:
        pass

def execute_ssh_bg(ip, cmds):
    if not cmds:
        return
        
    if isinstance(cmds, list):
        # 🚀 Command များကြားတွင် 1 စက္ကန့် နားပေးခြင်းဖြင့် ဆာဗာ Rate Limit (Overload) ကို ကာကွယ်မည်
        script_content = "\nsleep 1\n".join(cmds)
    else:
        script_content = cmds
        
    threading.Thread(target=_ssh_task, args=(ip, script_content), daemon=True).start()


# ---------------------------------------------------------
# 🚀 VLESS (v2) အတွက် Python JSON Editor
# Node ဆာဗာပေါ်တွင် Python ကို အသုံးပြု၍ JSON ဖိုင်ကို အမှားကင်းစွာ တည်းဖြတ်မည်
# ---------------------------------------------------------
def get_xray_json_remove_cmd(user_uuid):
    # ဤ Python Script အား ဆာဗာပေါ်တွင် ချက်ချင်း Run စေမည်
    py_script = f"""
import json
import sys

config_file = '/usr/local/etc/xray/config.json'
target_uuid = '{user_uuid}'

try:
    with open(config_file, 'r') as f:
        data = json.load(f)
        
    changed = False
    
    if 'inbounds' in data:
        for inbound in data['inbounds']:
            if inbound.get('protocol') == 'vless':
                if 'settings' in inbound and 'clients' in inbound['settings']:
                    original_clients = inbound['settings']['clients']
                    
                    new_clients = []
                    for c in original_clients:
                        if str(c.get('id')) != target_uuid:
                            new_clients.append(c)
                            
                    if len(new_clients) != len(original_clients):
                        inbound['settings']['clients'] = new_clients
                        changed = True

    if changed:
        with open(config_file, 'w') as f:
            json.dump(data, f, indent=4)
except Exception:
    sys.exit(1)
"""
    # Bash ၏ Here-Doc ကို အသုံးပြု၍ Python Script ကို Run မည်
    bash_cmd = f"""
cat << 'EOF' > /tmp/pm_remove_vless.py
{py_script.strip()}
EOF
python3 /tmp/pm_remove_vless.py
rm -f /tmp/pm_remove_vless.py
"""
    return bash_cmd.strip()


# ---------------------------------------------------------
# 🚀 DYNAMIC ACTION COMMANDS (Block / Unblock / Delete)
# ---------------------------------------------------------
def get_block_cmd(username, protocol, port, user_uuid):
    if protocol == 'v2':
        # Vless အတွက် JSON ထဲမှ အပြီးဖယ်ထုတ်မည် (Method B)
        return get_xray_json_remove_cmd(user_uuid)
    else:
        # Shadowsocks အတွက် UFW Firewall ဖြင့် Port ကို ပိတ်မည် (Method C)
        return f"ufw insert 1 deny {port}/tcp\nufw insert 1 deny {port}/udp"


def get_unblock_cmd(username, protocol, port, user_uuid):
    if protocol == 'v2':
        # Vless အတွက် Script ဖြင့် ပြန်ထည့်မည် (Script အဟောင်းက ထည့်သည့်အခါ လုံးဝအလုပ်လုပ်ပါသည်)
        return f"/usr/local/bin/v2ray-node-add-vless {username} {user_uuid}"
    else:
        # Shadowsocks အတွက် UFW Block ကို ပြန်ဖွင့်ပေးမည် (Method C)
        return f"ufw delete deny {port}/tcp\nufw delete deny {port}/udp\nufw allow {port}/tcp\nufw allow {port}/udp"


def get_safe_delete_cmd(username, protocol, port, user_uuid):
    if protocol == 'v2':
        # Vless ကို အပြီးဖျက်ရန် JSON မှ ဖယ်ထုတ်မည်
        return get_xray_json_remove_cmd(user_uuid)
    else:
        # Shadowsocks ကို အပြီးဖျက်ရန် Script အဟောင်းကို 'yes' ဖြင့် Auto-confirm လုပ်ပြီး UFW ပါ ရှင်းလင်းမည်
        return f"yes | /usr/local/bin/v2ray-node-del-out {username} {port}\nufw delete allow {port}/tcp\nufw delete allow {port}/udp\nufw delete deny {port}/tcp\nufw delete deny {port}/udp"
