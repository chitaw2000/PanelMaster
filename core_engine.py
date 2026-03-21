import subprocess
import threading
import base64

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

def get_safe_delete_cmd(username, protocol, port):
    if protocol == 'v2':
        # 🚀 Vless သည် Port 443 တစ်ခုတည်းကိုသာ အသေသုံးသဖြင့် မူလ Script အတိုင်းသာ ခေါ်မည်
        return f"yes | /usr/local/bin/v2ray-node-del-vless '{username}' >/dev/null 2>&1 || true"
    else:
        # 🚀 Outline SS သည် Port သီးသန့်သုံးသဖြင့် Zombie Port မဖြစ်စေရန် config.json မှ Port ကို အမြစ်ပြတ် ရှင်းထုတ်မည်
        py_clean = f"python3 -c \"import json; p='/usr/local/etc/xray/config.json'; d=json.load(open(p)); d['inbounds']=[i for i in d.get('inbounds',[]) if str(i.get('port',''))!='{port}']; json.dump(d,open(p,'w'),indent=4)\""
        
        script_cmd = f"yes | /usr/local/bin/v2ray-node-del-out '{username}' {port} >/dev/null 2>&1 || true"
        ufw_cmd = f"ufw delete allow {port}/tcp >/dev/null 2>&1 || true ; ufw delete allow {port}/udp >/dev/null 2>&1 || true"
        
        # သန့်ရှင်းရေးလုပ်ခြင်း၊ Script ခေါ်ခြင်း နှင့် Firewall ပိတ်ခြင်း တို့ကို ပေါင်း၍ Run မည်
        return f"{py_clean} ; {script_cmd} ; {ufw_cmd}"
