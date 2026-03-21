import subprocess
import threading
import base64
import uuid

# ---------------------------------------------------------
# 🚀 THE UNTOUCHABLE SSH ENGINE
# Command များကို Base64 ဖြင့် လုံခြုံစွာပို့ပြီး Race Condition မဖြစ်ရန် Task ID ခွဲမည်
# ---------------------------------------------------------
def _ssh_task(ip, script_content):
    try:
        b64 = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')
        task_id = str(uuid.uuid4())[:8]
        tmp_file = f"/tmp/pm_task_{task_id}.sh"
        
        full_cmd = f"ssh -o ConnectTimeout=20 -o StrictHostKeyChecking=no root@{ip} \"echo {b64} | base64 -d > {tmp_file} && bash {tmp_file} ; rm -f {tmp_file}\""
        subprocess.run(full_cmd, shell=True)
    except Exception:
        pass

def execute_ssh_bg(ip, cmds):
    if not cmds: 
        return
    if isinstance(cmds, list):
        script_content = "\n".join(cmds)
    else:
        script_content = cmds
    threading.Thread(target=_ssh_task, args=(ip, script_content), daemon=True).start()

# ---------------------------------------------------------
# 🚀 SAFE DELETE COMMAND
# ---------------------------------------------------------
def get_safe_delete_cmd(username, protocol, port):
    if protocol == 'v2':
        return f"yes | /usr/local/bin/v2ray-node-del-vless '{username}' >/dev/null 2>&1 || true"
    else:
        script_cmd = f"yes | /usr/local/bin/v2ray-node-del-out '{username}' {port} >/dev/null 2>&1 || true"
        ufw_cmd = f"ufw delete allow {port}/tcp >/dev/null 2>&1 || true\nufw delete allow {port}/udp >/dev/null 2>&1 || true"
        return f"{script_cmd}\n{ufw_cmd}"
