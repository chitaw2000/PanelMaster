import subprocess
import threading

def _ssh_task(ip, script_content):
    try:
        full_cmd = f"ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no root@{ip} \"{script_content}\""
        subprocess.run(full_cmd, shell=True)
    except Exception:
        pass

def execute_ssh_bg(ip, cmds):
    if not cmds: 
        return
        
    if isinstance(cmds, list):
        script_content = " ; ".join(cmds)
    else:
        script_content = cmds
        
    threading.Thread(target=_ssh_task, args=(ip, script_content), daemon=True).start()

def get_safe_delete_cmd(username, protocol, port):
    if protocol == 'v2':
        return f"yes | /usr/local/bin/v2ray-node-del-vless '{username}' >/dev/null 2>&1 || true"
    else:
        script_cmd = f"yes | /usr/local/bin/v2ray-node-del-out '{username}' {port} >/dev/null 2>&1 || true"
        ufw_cmd = f"ufw delete allow {port}/tcp >/dev/null 2>&1 || true ; ufw delete allow {port}/udp >/dev/null 2>&1 || true"
        return f"{script_cmd} ; {ufw_cmd}"
