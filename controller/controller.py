import subprocess
import time
import re
import requests
from datetime import datetime

# === Telegram Bot Configuration ===
TELEGRAM_BOT_TOKEN = 'YOUR_BOT_TOKEN_HERE'
TELEGRAM_CHAT_ID = 'YOUR_CHAT_ID_HERE'
TELEGRAM_API_URL = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage'

# === Alerting & Blocking Configuration ===
alert_log_path = '/home/tolay/alerts.log'
trace_pipe_path = '/sys/kernel/debug/tracing/trace_pipe'
alert_cooldown = 30  # seconds

# Track recent alerts to prevent duplicates
recent_alerts = {}

def send_telegram_alert(ip_address):
    message = f'🚨 DDoS Alert Detected\nSuspicious IP: {ip_address}\nTimestamp: {datetime.now()}'
    payload = {'chat_id': TELEGRAM_CHAT_ID, 'text': message}
    try:
        response = requests.post(TELEGRAM_API_URL, data=payload)
        if response.status_code != 200:
            print(f"[!] Telegram API Error: {response.text}")
    except Exception as e:
        print(f"[!] Telegram Error: {e}")

def block_ip(ip_address):
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
        print(f"[+] Blocked IP: {ip_address}")
    except subprocess.CalledProcessError:
        print(f"[!] Failed to block IP: {ip_address}")

def log_alert(ip_address):
    with open(alert_log_path, 'a') as log_file:
        log_file.write(f"{datetime.now()} - Blocked IP: {ip_address}\n")

def already_alerted(ip_address):
    now = time.time()
    last_alert_time = recent_alerts.get(ip_address, 0)
    if now - last_alert_time < alert_cooldown:
        return True
    recent_alerts[ip_address] = now
    return False

def monitor_trace_pipe():
    ip_pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
    print("[*] Monitoring trace_pipe for suspicious traffic...")
    
    try:
        with open(trace_pipe_path, 'r') as pipe:
            for line in pipe:
                match = ip_pattern.search(line)
                if match:
                    ip = match.group(1)
                    if not already_alerted(ip):
                        print(f"[!] Suspicious IP Detected: {ip}")
                        block_ip(ip)
                        log_alert(ip)
                        send_telegram_alert(ip)
    except PermissionError:
        print("[!] Permission denied. Try running with sudo.")
    except FileNotFoundError:
        print(f"[!] trace_pipe not found at {trace_pipe_path}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

if __name__ == '__main__':
    monitor_trace_pipe()
