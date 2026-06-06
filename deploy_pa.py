import requests
import time

username = 'fakhri269'
token = '262d0d5425a188173caab0e880029f7f50ce2397'
domain = f'{username}.pythonanywhere.com'
headers = {'Authorization': f'Token {token}'}
base = f'https://www.pythonanywhere.com/api/v0/user/{username}'

def check(r, label):
    print(f'{label}: [{r.status_code}]', r.text[:300])
    return r

# --- 1. Create Web App with Python 3.11 ---
print("\n=== STEP 1: Create WebApp ===")
r = requests.post(f'{base}/webapps/', headers=headers, data={
    'domain_name': domain,
    'python_version': 'python311'
})
check(r, "Create WebApp")

# --- 2. Set virtualenv (optional, skip for now) ---

# --- 3. Upload WSGI config ---
print("\n=== STEP 2: Upload WSGI ===")
wsgi = """
import os, sys
path = '/home/fakhri269/Nightprobe-Security/mysite'
if path not in sys.path:
    sys.path.insert(0, path)
os.environ['DJANGO_SETTINGS_MODULE'] = 'mysite.settings'
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
"""
wsgi_path = f'/var/www/{username}_pythonanywhere_com_wsgi.py'
r = requests.post(
    f'{base}/files/path{wsgi_path}',
    headers=headers,
    files={'content': ('wsgi.py', wsgi, 'text/plain')}
)
check(r, "Upload WSGI")

# --- 4. Create a bash console and run setup commands ---
print("\n=== STEP 3: Open Console ===")
r = requests.post(f'{base}/consoles/', headers=headers, data={'executable': 'bash', 'arguments': ''})
check(r, "Open Console")
if r.status_code != 201:
    print("ERROR: Cannot open console. Stop.")
    exit(1)

console_id = r.json()['id']
print(f"Console ID: {console_id}")

def run(cmd, wait=3):
    print(f"  >> {cmd}")
    requests.post(
        f'{base}/consoles/{console_id}/send_input/',
        headers=headers,
        json={'input': cmd + '\n'}
    )
    time.sleep(wait)

# --- 5. Setup repo ---
print("\n=== STEP 4: Setup Repo ===")
run("cd ~ && rm -rf Nightprobe-Security", wait=3)
run("git clone https://github.com/Fakhri269/Nightprobe-Security.git", wait=15)
run("cd ~/Nightprobe-Security/mysite && pip3.11 install --user -r requirements.txt", wait=60)
run("cd ~/Nightprobe-Security/mysite && python3.11 manage.py migrate", wait=10)
run("cd ~/Nightprobe-Security/mysite && python3.11 manage.py collectstatic --noinput", wait=5)

# --- Get console output to verify ---
time.sleep(3)
r = requests.get(f'{base}/consoles/{console_id}/get_latest_output/', headers=headers)
print("\nConsole output:", r.text[:1000])

# --- 6. Reload WebApp ---
print("\n=== STEP 5: Reload WebApp ===")
r = requests.post(f'{base}/webapps/{domain}/reload/', headers=headers)
check(r, "Reload WebApp")

# --- Cleanup console ---
requests.delete(f'{base}/consoles/{console_id}/', headers=headers)

print("\n=============================")
print("DONE!")
print(f"Backend: https://{domain}")
print(f"Test:    https://{domain}/scan/?url=https://example.com")
print("=============================")
