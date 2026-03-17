import os, time, base64
from config import NODES_LIST

USER_ACTIVITY = {}
ACTIVE_WINDOW = 60

def get_nodes():
    nodes = {}
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, "r") as f:
            for line in f:
                if line.strip() and len(line.split()) >= 2:
                    nodes[line.split()[0]] = line.split()[1]
    return nodes

def check_live_status(db):
    current_time = time.time()
    active_set = set()
    for uname, info in db.items():
        try: curr_bytes = float(info.get('used_bytes') or 0)
        except: curr_bytes = 0.0
        
        if uname not in USER_ACTIVITY:
            USER_ACTIVITY[uname] = {'bytes': curr_bytes, 'time': 0}
        else:
            if curr_bytes > USER_ACTIVITY[uname]['bytes']:
                USER_ACTIVITY[uname]['bytes'] = curr_bytes
                USER_ACTIVITY[uname]['time'] = current_time
                
        if (current_time - USER_ACTIVITY[uname]['time']) <= ACTIVE_WINDOW:
            active_set.add(uname)
    return active_set

def get_safe_delete_cmd(username, protocol, port):
    py_script = f"""
import json
try:
    path = '/usr/local/etc/xray/config.json'
    with open(path, 'r') as f: d = json.load(f)
    changed = False
    new_inbounds = []
    for ib in d.get('inbounds', []):
        if '{protocol}' == 'out' and str(ib.get('port')) == str('{port}'):
            changed = True
            continue
        if '{protocol}' == 'v2' and 'settings' in ib and 'clients' in ib['settings']:
            orig_len = len(ib['settings']['clients'])
            ib['settings']['clients'] = [c for c in ib['settings']['clients'] if c.get('email') != '{username}']
            if len(ib['settings']['clients']) != orig_len: changed = True
        new_inbounds.append(ib)
    if changed:
        d['inbounds'] = new_inbounds
        with open(path, 'w') as f: json.dump(d, f, indent=2)
except Exception as e: pass
"""
    b64_script = base64.b64encode(py_script.encode()).decode()
    return f"echo {b64_script} | base64 -d | python3"
