import importlib.util, traceback
from starlette.requests import Request
out_path = r'c:\Users\phimane.tiaokhiao\OneDrive - AMN Healthcare, Inc\AMN\GitHub\Cisco_CUCM\_menu_probe_out.txt'
try:
    spec = importlib.util.spec_from_file_location('appmod', r'c:\Users\phimane.tiaokhiao\OneDrive - AMN Healthcare, Inc\AMN\GitHub\Cisco_CUCM\main.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    scope = {'type':'http','method':'GET','path':'/menu','headers':[], 'query_string': b'', 'client': ('127.0.0.1', 1234), 'server': ('test', 80), 'scheme':'http'}
    req = Request(scope)
    resp = mod.menu_page(req)
    body = getattr(resp, 'body', b'') or b''
    text = f'type={type(resp)}\nstatus={getattr(resp, "status_code", None)}\nbody={body[:200]!r}\n'
except Exception:
    text = traceback.format_exc()
with open(out_path, 'w', encoding='utf-8') as fh:
    fh.write(text)
print(out_path)
