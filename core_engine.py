import subprocess
import threading

# 🚀 THE UNTOUCHABLE SSH ENGINE (Background တွင် အေးဆေးစွာ အလုပ်လုပ်မည်)
def _ssh_task(ip, cmd):
    # Command မပြတ်ကျစေရန် Thread ဖြင့် သေချာပေါက် အဆုံးထိ စောင့် Run မည်
    full_cmd = f"ssh -o ConnectTimeout=20 -o StrictHostKeyChecking=no root@{ip} \"{cmd}\""
    subprocess.run(full_cmd, shell=True)

def execute_ssh_isolated(ip, cmd):
    """ဒီ Function က UI ကို မစောင့်စေဘဲ နောက်ကွယ်ကနေ သေချာပေါက် Command များကို အလုပ်လုပ်ပေးမည်"""
    threading.Thread(target=_ssh_task, args=(ip, cmd), daemon=True).start()

# 🚀 မူရင်းအတိုင်း ၁၀၀% အလုပ်လုပ်ခဲ့သော Safe Delete Script
def get_safe_delete_script(username, protocol, port):
    if protocol == 'v2':
        return f"/usr/local/bin/v2ray-node-del-vless '{username}'"
    else:
        return f"/usr/local/bin/v2ray-node-del-out '{username}' {port} ; ufw delete allow {port}/tcp ; ufw delete allow {port}/udp"
