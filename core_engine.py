import subprocess
import threading

def _ssh_task(ip, script_content):
    try:
        # ဘာ Hack မှမပါဘဲ ရိုးရိုးရှင်းရှင်းနှင့် အသေချာဆုံး SSH လှမ်းခေါ်မည်
        full_cmd = f"ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no root@{ip} \"{script_content}\""
        subprocess.run(full_cmd, shell=True)
    except Exception:
        pass

def execute_ssh_bg(ip, cmds):
    if not cmds: 
        return
        
    if isinstance(cmds, list):
        # 🚀 Bulk ထုတ်ပါက ဖိုင်လုရေးခြင်းမဖြစ်စေရန် Command များကြားတွင် ၀.၅ စက္ကန့် နားပေးမည်
        script_content = " ; sleep 0.5 ; ".join(cmds)
    else:
        script_content = cmds
        
    threading.Thread(target=_ssh_task, args=(ip, script_content), daemon=True).start()

# ---------------------------------------------------------
# Safe Delete, Block, Unblock Commands
# ---------------------------------------------------------
def get_safe_delete_cmd(username, protocol, port):
    if protocol == 'v2':
        return f"yes | /usr/local/bin/v2ray-node-del-vless {username} >/dev/null 2>&1 || true"
    else:
        script_cmd = f"yes | /usr/local/bin/v2ray-node-del-out {username} {port} >/dev/null 2>&1 || true"
        ufw_cmd = f"ufw delete allow {port}/tcp >/dev/null 2>&1 || true ; ufw delete allow {port}/udp >/dev/null 2>&1 || true ; ufw delete deny {port}/tcp >/dev/null 2>&1 || true ; ufw delete deny {port}/udp >/dev/null 2>&1 || true"
        return f"{script_cmd} ; {ufw_cmd}"

def get_block_cmd(username, protocol, port):
    if protocol == 'v2':
        # Vless ကို ယာယီပိတ်ရန် ဆာဗာမှ ဖျက်ထုတ်လိုက်မည် (ပြန်ဖွင့်လျှင် မူလ UUID ဖြင့် ပြန်ထည့်မည်)
        return f"yes | /usr/local/bin/v2ray-node-del-vless {username} >/dev/null 2>&1 || true"
    else:
        # Shadowsocks ကို UFW မှ ဖြတ်ချမည်
        return f"ufw insert 1 deny {port}/tcp >/dev/null 2>&1 || true ; ufw insert 1 deny {port}/udp >/dev/null 2>&1 || true"
