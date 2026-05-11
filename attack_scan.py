import socket
import datetime
import time
import random

# 1. 환경 설정
target_ip = "192.168.2.100"
log_file = "port_scan_bypassed.log"

# 2. 목표 수치: 1,000개 포트 스캔
START_PORT = 1
END_PORT = 1000

def write_log(message: str) -> None:
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(message + "\n")

print(f"📡 [데이터 수집 시작] 포트 스캔 (미탐): {target_ip}의 {START_PORT}~{END_PORT}번 포트를 점검합니다.")

# 3. 스캔 엔진
for port in range(START_PORT, END_PORT + 1):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 100단위로 진행 상황 출력
    if port % 100 == 0:
        print(f"🔍 현재 스캔 진행 중: {port} / 1000 포트 완료")

    try:
        # 소켓 설정 (AF_INET: IPv4, SOCK_STREAM: TCP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1) # 빠른 스캔을 위해 타임아웃을 짧게 설정
        
        # 포트 접속 시도
        result = sock.connect_ex((target_ip, port))
        
        if result == 0:
            status = "OPEN"
        else:
            status = "CLOSED"
            
        log_line = f"{now} | PORT_SCAN | target={target_ip} | port={port} | status={status}"
        write_log(log_line)
        
        sock.close()

    except Exception as e:
        log_line = f"{now} | PORT_SCAN | port={port} | error={e}"
        write_log(log_line)

    # ⏱ AI가 '비정상적 속도'를 학습할 수 있도록 아주 짧은 간격 설정
    time.sleep(0.01)

print(f"\n✨ 수집 완료! '{log_file}' 파일에 1,000개의 스캔 기록이 저장되었습니다.")
