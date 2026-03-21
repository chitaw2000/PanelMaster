import subprocess
import threading

# ---------------------------------------------------------
# 🚀 THE PURE SSH ENGINE (No Hacks, No Base64)
# ဆာဗာဆီသို့ Command များကို တိုက်ရိုက် အမှားကင်းစွာ လှမ်းပို့မည်
# ---------------------------------------------------------
def _ssh_task(ip, cmd_string):
    try:
        # အရိုးရှင်းဆုံးနှင့် အသေချာဆုံး SSH ချိတ်ဆက်မှု
        full_cmd = f"ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no root@{ip} \"{cmd_string}\""
        subprocess.run(full_cmd, shell=True)
    except Exception:
        pass

def execute_ssh_bg(ip, cmds):
    if not cmds: 
        return
        
    if isinstance(cmds, list):
        # 🚀 X-ray Crash မဖြစ်စေရန် Command များကြားတွင် ၁ စက္ကန့် နားပေးမည်
        cmd_string = " ; sleep 1 ; ".join(cmds)
    else:
        cmd_string = cmds
        
    threading.Thread(target=_ssh_task, args=(ip, cmd_string), daemon=True).start()

# ---------------------------------------------------------
# 🚀 DIRECT ACTION COMMANDS 
# မူလ Script များကိုသာ အသုံးပြုမည် (yes | ခံပေးခြင်းဖြင့် prompt များကို ကျော်မည်)
# ---------------------------------------------------------

def get_safe_delete_cmd(username, protocol, port, user_uuid=""):
    if protocol == 'v2':
        return f"yes | /usr/local/bin/v2ray-node-del-vless {username} >/dev/null 2>&1 || true"
    else:
        # Shadowsocks အတွက် Script အပြင် UFW Port ပါ ရှင်းလင်းမည်
        script_cmd = f"yes | /usr/local/bin/v2ray-node-del-out {username} {port} >/dev/null 2>&1 || true"
        ufw_cmd = f"ufw delete allow {port}/tcp >/dev/null 2>&1 || true ; ufw delete allow {port}/udp >/dev/null 2>&1 || true ; ufw delete deny {port}/tcp >/dev/null 2>&1 || true ; ufw delete deny {port}/udp >/dev/null 2>&1 || true"
        return f"{script_cmd} ; {ufw_cmd}"

def get_block_cmd(username, protocol, port, user_uuid=""):
    if protocol == 'v2':
        # Vless ကို ယာယီပိတ်ရန် ဖျက်ထုတ်လိုက်မည် (ပြန်ဖွင့်လျှင် UUID အဟောင်းဖြင့် ပြန်ထည့်မည်)
        return f"yes | /usr/local/bin/v2ray-node-del-vless {username} >/dev/null 2>&1 || true"
    else:
        # Shadowsocks ကို UFW မှ ဖြတ်ချမည်
        return f"ufw insert 1 deny {port}/tcp >/dev/null 2>&1 || true ; ufw insert 1 deny {port}/udp >/dev/null 2>&1 || true"

def get_unblock_cmd(username, protocol, port, user_uuid=""):
    if protocol == 'v2':
        # Vless ပြန်ဖွင့်ရန် မူလ UUID ဖြင့် ပြန်ထည့်မည်
        return f"/usr/local/bin/v2ray-node-add-vless {username} {user_uuid} >/dev/null 2>&1 || true"
    else:
        # Shadowsocks ပြန်ဖွင့်ရန် UFW Block ကို ဖြုတ်မည်
        return f"ufw delete deny {port}/tcp >/dev/null 2>&1 || true ; ufw delete deny {port}/udp >/dev/null 2>&1 || true"
