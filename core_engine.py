import subprocess
import threading
import base64
import uuid

# ---------------------------------------------------------
# 🚀 THE UNTOUCHABLE SSH ENGINE
# Command များကို Base64 ပြောင်း၍ Bash Script အဖြစ် သေချာပေါက် Run မည်
# ---------------------------------------------------------
def _ssh_task(ip, script_content):
    try:
        b64 = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')
        
        # 🚀 Bulk ဖျက်သည့်အခါ /tmp ဖိုင်များ Overwrite မဖြစ်စေရန် Task ID ဖြင့် သီးသန့်ခွဲထုတ်ပေးပါသည်
        task_id = str(uuid.uuid4())[:8]
        tmp_file = f"/tmp/pm_{task_id}.sh"
        
        full_cmd = f"ssh -o ConnectTimeout=20 -o StrictHostKeyChecking=no root@{ip} \"echo {b64} | base64 -d > {tmp_file} && bash {tmp_file} && rm -f {tmp_file}\""
        subprocess.run(full_cmd, shell=True)
    except Exception:
        pass

def execute_ssh_bg(ip, cmds):
    if not cmds: 
        return
        
    if isinstance(cmds, list):
        # 🚀 Command များကြားတွင် 1 စက္ကန့် နားပေးခြင်းဖြင့် ဆာဗာ Overload ကို ကာကွယ်မည်
        script_content = "\nsleep 1\n".join(cmds)
    else:
        script_content = cmds
        
    threading.Thread(target=_ssh_task, args=(ip, script_content), daemon=True).start()

# ---------------------------------------------------------
# 🚀 VLESS (v2) အတွက် Python JSON Editor
# ---------------------------------------------------------
def get_vless_remove_cmd(user_uuid):
    # Python Script ကို ယာယီဖိုင်အဖြစ် ဆာဗာပေါ်တွင် ရေး၍ Run မည်
    py_script = f"""
import json
import os

try:
    with open('/usr/local/etc/xray/config.json', 'r') as f:
        data = json.load(f)
        
    changed = False
    if 'inbounds' in data:
        for inbound in data['inbounds']:
            if inbound.get('protocol') == 'vless':
                clients = inbound.get('settings', {{}}).get('clients', [])
                new_clients = []
                for c in clients:
                    if str(c.get('id')) != '{user_uuid}':
                        new_clients.append(c)
                        
                if len(new_clients) != len(clients):
                    inbound['settings']['clients'] = new_clients
                    changed = True
                    
    if changed:
        with open('/usr/local/etc/xray/config.json', 'w') as f:
            json.dump(data, f, indent=4)
except Exception:
    pass
"""
    # Unique ဖိုင်နာမည်ပေးခြင်းဖြင့် Race Condition ပြဿနာကို တားဆီးမည်
    tmp_py = f"/tmp/rm_vless_{user_uuid}.py"
    bash_cmd = f"""
cat << 'EOF' > {tmp_py}
{py_script.strip()}
EOF
python3 {tmp_py}
rm -f {tmp_py}
"""
    return bash_cmd.strip()

# ---------------------------------------------------------
# 🚀 DYNAMIC ACTION COMMANDS (Block / Unblock / Delete)
# ---------------------------------------------------------
def get_block_cmd(username, protocol, port, user_uuid=""):
    if protocol == 'v2':
        return get_vless_remove_cmd(user_uuid)
    else:
        return f"ufw insert 1 deny {port}/tcp >/dev/null 2>&1 || true\nufw insert 1 deny {port}/udp >/dev/null 2>&1 || true"

def get_unblock_cmd(username, protocol, port, user_uuid=""):
    if protocol == 'v2':
        return f"/usr/local/bin/v2ray-node-add-vless '{username}' '{user_uuid}' >/dev/null 2>&1 || true"
    else:
        return f"ufw delete deny {port}/tcp >/dev/null 2>&1 || true\nufw delete deny {port}/udp >/dev/null 2>&1 || true\nufw allow {port}/tcp >/dev/null 2>&1 || true\nufw allow {port}/udp >/dev/null 2>&1 || true"

def get_safe_delete_cmd(username, protocol, port, user_uuid=""):
    if protocol == 'v2':
        return get_vless_remove_cmd(user_uuid)
    else:
        script_cmd = f"yes | /usr/local/bin/v2ray-node-del-out '{username}' {port} >/dev/null 2>&1 || true"
        ufw_cmd = f"ufw delete allow {port}/tcp >/dev/null 2>&1 || true\nufw delete allow {port}/udp >/dev/null 2>&1 || true\nufw delete deny {port}/tcp >/dev/null 2>&1 || true\nufw delete deny {port}/udp >/dev/null 2>&1 || true"
        return f"{script_cmd}\n{ufw_cmd}"
