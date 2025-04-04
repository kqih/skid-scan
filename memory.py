import psutil
import re
import ctypes
import ctypes.wintypes
import threading
import time
import requests
import argparse
import sys

BLACKLISTED_PROCESSES = {proc.lower() for proc in {"chrome.exe", "discord.exe", "explorer.exe", "conhost.exe", "docker.exe"}}
WEBHOOK_REGEX = rb'https://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+'
BOT_TOKEN_REGEX = rb'([A-Za-z\d]{24})\.([A-Za-z\d]{6})\.([A-Za-z\d_-]{27})'
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

OpenProcess = ctypes.windll.kernel32.OpenProcess
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
CloseHandle = ctypes.windll.kernel32.CloseHandle
VirtualQueryEx = ctypes.windll.kernel32.VirtualQueryEx

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.wintypes.LPVOID),
        ("AllocationBase", ctypes.wintypes.LPVOID),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.wintypes.DWORD),
        ("Protect", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
    ]

seen_pids = set()
start_time = time.time()
tracked_data = {}
REPORT_WEBHOOK = None

def is_valid_webhook(webhook_url):
    try:
        response = requests.get(webhook_url, timeout=5)
        return "id" in response.text
    except requests.RequestException:
        return False

def is_valid_bot_token(bot_token):
    try:
        headers = {"Authorization": f"Bot {bot_token}"}
        response = requests.get("https://discord.com/api/v10/users/@me", headers=headers, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def scan_process_memory(pid):
    try:
        process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not process_handle:
            return [], []

        webhooks, bot_tokens = [], []
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0

        while VirtualQueryEx(process_handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.State == 0x1000 and mbi.Protect in (0x02, 0x04, 0x20, 0x40):
                buffer = ctypes.create_string_buffer(mbi.RegionSize)
                bytes_read = ctypes.c_size_t()

                if ReadProcessMemory(process_handle, ctypes.c_void_p(addr), buffer, mbi.RegionSize, ctypes.byref(bytes_read)):
                    found_webhooks = re.findall(WEBHOOK_REGEX, buffer.raw)
                    found_tokens = re.findall(BOT_TOKEN_REGEX, buffer.raw)
                    formatted_tokens = [b".".join(token).decode() for token in found_tokens]
                    webhooks.extend(found_webhooks)
                    bot_tokens.extend(formatted_tokens)

            addr += mbi.RegionSize

        CloseHandle(process_handle)
        return webhooks, bot_tokens
    except Exception:
        return [], []

def report_to_discord(process_name, pid, webhooks, bot_tokens):
    if not REPORT_WEBHOOK:
        print("Error: REPORT_WEBHOOK is not defined.")
        return

    unique_webhooks = list(set(webhooks))
    unique_tokens = list(set(bot_tokens))

    if not unique_webhooks and not unique_tokens:
        return

    embed = {
        "title": "⚠️ Detected!",
        "color": 16711680,
        "fields": [{"name": "🖥️ Process", "value": f"{process_name} (PID: {pid})", "inline": False}],
    }

    if unique_webhooks:
        embed["fields"].append({"name": "🌐 Webhooks", "value": "\n".join(unique_webhooks), "inline": False})

    if unique_tokens:
        embed["fields"].append({"name": "🔑 Bot Tokens", "value": "\n".join(unique_tokens), "inline": False})

    data = {"embeds": [embed]}
    try:
        requests.post(REPORT_WEBHOOK, json=data, timeout=5)
    except requests.RequestException as e:
        print(f"Error sending report to Discord: {e}")

def monitor_new_processes():
    global seen_pids
    while True:
        current_pids = set(psutil.pids())
        for pid in current_pids - seen_pids:
            try:
                process = psutil.Process(pid)
                name = process.name().lower()
                if process.create_time() < start_time:
                    continue
                if name in BLACKLISTED_PROCESSES:
                    continue
                print(f"[+] New process detected: {name} (PID: {pid})")
                seen_pids.add(pid)
                tracked_data[pid] = {"webhooks": set(), "tokens": set()}
                threading.Thread(target=scan_process_continuously, args=(pid, name), daemon=True).start()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        time.sleep(1)

def scan_process_continuously(pid, process_name):
    while True:
        try:
            process = psutil.Process(pid)
            webhooks, bot_tokens = scan_process_memory(pid)
            new_webhooks = [w.decode() for w in webhooks if w.decode() not in tracked_data[pid]["webhooks"]]
            new_tokens = [t for t in bot_tokens if t not in tracked_data[pid]["tokens"]]
            valid_webhooks = [w for w in new_webhooks if is_valid_webhook(w)]
            valid_tokens = [t for t in new_tokens if is_valid_bot_token(t)]

            if valid_webhooks or valid_tokens:
                print(f"[!] New valid credentials found in {process_name} (PID: {pid}):")
                for webhook in valid_webhooks:
                    print(f"  🌐 Webhook: {webhook}")
                for token in valid_tokens:
                    print(f"  🔑 Bot Token: {token}")
                report_to_discord(process_name, pid, valid_webhooks, valid_tokens)

            tracked_data[pid]["webhooks"].update(new_webhooks)
            tracked_data[pid]["tokens"].update(new_tokens)
            time.sleep(3)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            print(f"[-] Process exited: {process_name} (PID: {pid})")
            tracked_data.pop(pid, None)
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor processes for Discord webhooks and bot tokens.")
    parser.add_argument("report_webhook", help="The Discord webhook URL to send reports to.")
    args = parser.parse_args()

    REPORT_WEBHOOK = args.report_webhook

    print("[*] Monitoring new processes")
    monitor_thread = threading.Thread(target=monitor_new_processes, daemon=True)
    monitor_thread.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Scanner stopped.")
