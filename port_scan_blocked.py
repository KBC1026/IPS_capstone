import socket
import time
from datetime import datetime

# ==========================================
# 1. 설정값
# ==========================================
TARGET_IP = "192.168.2.100"
TOTAL_PORTS = 1000  # 목표 데이터 개수에 맞춰 1000개로 수정
LOG_FILE = "port_scan_blocked.log"

def run_port_scan():
    print(f"[*] 포트 스캔 탐지 데이터 수집 시작 (목표: {TOTAL_PORTS}개)")
    print(f"[*] 타겟: {TARGET_IP}")
    print("-" * 50)

    success_count = 0

    with open(LOG_FILE, "a") as f:
        for port in range(1, TOTAL_PORTS + 1):
            try:
                # 소켓 생성 (TCP 연결 시도)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.05) # 빠른 스캔을 위해 타임아웃 단축

                # 포트 연결 시도
                result = s.connect_ex((TARGET_IP, port))
                status = "OPEN" if result == 0 else "CLOSED/FILTERED"

                # 칼리 로컬 로그 기록 (참고용)
                log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] PORT: {port} | Status: {status}\n"
                f.write(log_entry)

                success_count += 1

                # 50개마다 진행 상황 출력
                if port % 50 == 0:
                    print(f"[+] {port}/{TOTAL_PORTS} 완료... (진행률: {(port/TOTAL_PORTS)*100:.1f}%)")

            except Exception as e:
                print(f"\n[!] 에러 발생 (포트 {port}): {e}")
                break
            
            finally:
                # 에러 발생 여부와 상관없이 무조건 소켓을 닫아 메모리 누수 방지
                s.close()

            time.sleep(0.01) # 수리카타가 패킷을 분석하고 로그를 남길 최소한의 여유 시간

    print("-" * 50)
    print(f"[*] 수집 종료! 총 {success_count}개의 스캔 기록이 생성되었습니다.")

if __name__ == "__main__":
    run_port_scan()
