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
        # 🚀 Command တစ်ခုချင်းစီကြားတွင် 1 စက္ကန့် နားပေးခြင်းဖြင့် ဆာဗာ Overload ကို ကာကွယ်မည်
        script_content = "\nsleep 1\n".join(cmds)
    else:
        script_content = cmds
        
    threading.Thread(target=_ssh_task, args=(ip, script_content), daemon=True).start()

# ---------------------------------------------------------
# 🚀 SAFE DELETE COMMAND
# ဖျက်လိုက်တာတောင် ချိတ်ရနေတဲ့ ပြဿနာကို အမြစ်ပြတ် ရှင်းမည့် Command
# ---------------------------------------------------------
def get_safe_delete_cmd(username, protocol, port):
    # Quotes ဖယ်ထားပေးပြီး echo 'y' ဖြင့် သေချာပေါက် အတည်ပြုစေမည်
    if protocol == 'v2':
        return f"echo 'y' | /usr/local/bin/v2ray-node-del-vless {username} >/dev/null 2>&1 || true"
    else:
        # Out (Shadowsocks) အတွက် UFW Port ပါ တစ်ခါတည်း သေချာ ပိတ်မည်
        return f"echo 'y' | /usr/local/bin/v2ray-node-del-out {username} {port} >/dev/null 2>&1 || true\nufw delete allow {port}/tcp >/dev/null 2>&1 || true\nufw delete allow {port}/udp >/dev/null 2>&1 || true"
