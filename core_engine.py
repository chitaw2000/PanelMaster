import subprocess
import threading
import base64

def _ssh_task(ip, script_content):
    try:
        # မင်းအတည်ပြုထားသော အလုပ်အလုပ်ဆုံး မူရင်းစနစ်ကိုသာ ပြန်သုံးထားပါသည်
        b64 = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')
        full_cmd = f"ssh -o ConnectTimeout=20 -o StrictHostKeyChecking=no root@{ip} \"echo {b64} | base64 -d > /tmp/pm_task.sh && bash /tmp/pm_task.sh\""
        subprocess.run(full_cmd, shell=True)
    except Exception:
        pass

def execute_ssh_bg(ip, cmds):
    if not cmds: 
        return
    if isinstance(cmds, list):
        # 🚀 Bulk ထုတ်ပါက ဖိုင်လုရေးခြင်းမဖြစ်စေရန် 1 စက္ကန့် နားပေးမည်
        script_content = "\nsleep 1\n".join(cmds)
    else:
        script_content = cmds
    threading.Thread(target=_ssh_task, args=(ip, script_content), daemon=True).start()

def get_safe_delete_cmd(username, protocol, port):
    if protocol == 'v2':
        return f"yes | /usr/local/bin/v2ray-node-del-vless '{username}' >/dev/null 2>&1 || true"
    else:
        return f"yes | /usr/local/bin/v2ray-node-del-out '{username}' {port} >/dev/null 2>&1 || true ; ufw delete allow {port}/tcp >/dev/null 2>&1 || true ; ufw delete allow {port}/udp >/dev/null 2>&1 || true"

def get_block_cmd(username, protocol, port):
    # Block လုပ်လျှင်လည်း ဆာဗာမှ ယာယီဖယ်ထုတ်ထားလိုက်မည်
    return get_safe_delete_cmd(username, protocol, port)
