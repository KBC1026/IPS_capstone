import joblib
import pandas as pd
from scapy.all import sniff, IP, TCP, Raw
import re
from collections import defaultdict
import time
import warnings

warnings.filterwarnings("ignore")

# 💡 모델 경로 및 네트워크 설정
MODEL_PATH = '/home/kbc/ips-security_capstone_projects/ai_ips_model_v4.pkl'
INTERFACE = 'ens18'
ATTACKER_IP = '117.16.174.60'

print("[*] 업그레이드된 AI 침입 탐지 시스템(V3.4 - 정밀도 분석 모드) 부팅 중...")
try:
    rf_model = joblib.load(MODEL_PATH)
    print("✅ V3.0 확률 기반 AI 모델 로딩 완료!")
    print("📢 각 탐지 결과에 AI 확신도(%)가 함께 출력됩니다.")
except Exception as e:
    print(f"❌ 모델 로드 실패: {e}")
    exit()

login_fails = defaultdict(int)
last_log_time = defaultdict(float)
last_packet_time = defaultdict(float)
TARGET_PORTS = [21, 22, 80, 3306, 5000]

def log_attack(message, attack_type):
    current_time = time.time()
    if current_time - last_log_time[attack_type] < 3.0:
        return
    print(message)
    last_log_time[attack_type] = current_time

def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src

        if src_ip != ATTACKER_IP: return
        dst_port = packet[TCP].dport
        if dst_port not in TARGET_PORTS: return

        current_time = time.time()

        # 세션 타임아웃 (5초)
        if current_time - last_packet_time[src_ip] > 5.0:
            login_fails[src_ip] = 0

        last_packet_time[src_ip] = current_time

        payload_str = ""

        if not packet.haslayer(Raw):
            if packet[TCP].flags == 'A':
                return
        else:
            try:
                payload_str = packet[Raw].load.decode('utf-8', errors='ignore')
                if "POST" in payload_str:
                    login_fails[src_ip] += 1
            except: pass

        # 💡 [변경됨] 특수문자와 SQL 키워드를 완벽하게 분리해서 검사합니다!
        # 1. 특수문자 개수 (해킹에 자주 쓰이는 기호들)
        special_chars = re.findall(r"['\";<>|]|--", payload_str)
        special_char_count = len(special_chars)

        # 2. SQL 전용 키워드 개수 (대소문자 무관)
        sql_keywords = re.findall(r"\bSELECT\b|\bUNION\b|\bDROP\b|\bINSERT\b|\bUPDATE\b|\bWHERE\b|\bAND\b|\bOR\b", payload_str, re.IGNORECASE)
        sql_keyword_count = len(sql_keywords)

        # 💡 [핵심] 코랩에서 학습한 5과목 순서와 정확하게 일치하는 데이터프레임 생성
        features = pd.DataFrame([{
            'dst_port': dst_port,
            'special_char_count': special_char_count,
            'sql_keyword_count': sql_keyword_count,  # 새로 추가된 핵심 룰!
            'login_fail_count': login_fails[src_ip],
            'packet_length': len(packet)
        }])

        # 확률(확신도) 추출 로직
        probs = rf_model.predict_proba(features)[0]
        max_prob = max(probs)
        prob_percent = round(max_prob * 100, 1) # 예: 85.2%
        prediction = list(probs).index(max_prob)

        # 라벨 매핑 딕셔너리
        labels = {0: "정상", 1: "포트스캔", 2: "SQLi", 3: "브루트포스"}
        predicted_name = labels.get(prediction, "알수없음")

        # 70% 미만일 때: 왜 신종 공격으로 뺐는지 분석하기 위해 출력
        if max_prob < 0.70:
            msg = f"[⚠️ Anomaly] 신종/이상 트래픽 의심 (AI 최상위 예측: {predicted_name} {prob_percent}%)"
            log_attack(msg, "Anomaly")
        else:
            # 70% 이상일 때: 명확한 탐지 확신도 출력
            msg = f"[🚨 AI 탐지] 공격지: {ATTACKER_IP} | 유형: {predicted_name} (확신도: {prob_percent}%)"
            if prediction == 1: log_attack(msg, "Port Scan")
            elif prediction == 2: log_attack(msg, "SQL Injection")
            elif prediction == 3: log_attack(msg, "Brute Force")

print(f"[*] 실시간 네트워크 감시 시작 (인터페이스: {INTERFACE})")
sniff(iface=INTERFACE, prn=process_packet, store=False)
