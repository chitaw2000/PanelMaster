import subprocess
import threading
import base64

# 🚀 THE UNTOUCHABLE SSH ENGINE: Command များကို Base64 ပြောင်း၍ Bash Script အဖြစ် သေချာပေါက် Run မည်
def _ssh_task(ip, script_content):
    try:
        b64 = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')
        full_cmd = f"ssh -o ConnectTimeout=20 -o StrictHostKeyChecking=no root@{ip} \"echo {b64} | base64 -d > /tmp/pm_task.sh && bash /tmp/pm_task.sh\""
        subprocess.run(full_cmd, shell=True)
    except Exception:
        pass

def execute_ssh_bg(ip, cmds):
    if not cmds: return
    if isinstance(cmds, list):
        script_content = "\n".join(cmds)
    else:
        script_content = cmds
    threading.Thread(target=_ssh_task, args=(ip, script_content), daemon=True).start()

# 🚀 မူရင်းအတိုင်း ၁၀၀% အလုပ်လုပ်ခဲ့သော Safe Delete Script (Hang မဖြစ်ရန် ကာကွယ်ထားသည်)
def get_safe_delete_cmd(username, protocol, port):
    if protocol == 'v2':
        return f"yes | /usr/local/bin/v2ray-node-del-vless '{username}' >/dev/null 2>&1 || true"
    else:
        return f"yes | /usr/local/bin/v2ray-node-del-out '{username}' {port} >/dev/null 2>&1 || true ; ufw delete allow {port}/tcp >/dev/null 2>&1 || true ; ufw delete allow {port}/udp >/dev/null 2>&1 || true"
