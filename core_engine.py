import subprocess
import threading

def _ssh_task(ip, script_content):
    try:
        # ဘာ Hack မှမပါဘဲ ရိုးရိုးရှင်းရှင်း တိုက်ရိုက်ခေါ်မည်
        full_cmd = f"ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no root@{ip} \"{script_content}\""
        subprocess.run(full_cmd, shell=True)
    except Exception:
        pass

def execute_ssh_bg(ip, cmds):
    if not cmds: return
    if isinstance(cmds, list):
        # Command များကြားတွင် 0.5 စက္ကန့် နားပေးမည် (Bulk ထုတ်ပါက Error မတက်စေရန်)
        script_content = " ; sleep 0.5 ; ".join(cmds)
    else:
        script_content = cmds
    threading.Thread(target=_ssh_task, args=(ip, script_content), daemon=True).start()

def get_safe_delete_cmd(username, protocol, port):
    if protocol == 'v2':
        return f"yes | /usr/local/bin/v2ray-node-del-vless '{username}' >/dev/null 2>&1 || true"
    else:
        return f"yes | /usr/local/bin/v2ray-node-del-out '{username}' {port} >/dev/null 2>&1 || true ; ufw delete allow {port}/tcp >/dev/null 2>&1 || true ; ufw delete allow {port}/udp >/dev/null 2>&1 || true"
