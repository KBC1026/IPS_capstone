import joblib
import pandas as pd
from scapy.all import sniff, IP, TCP, Raw
import re
from collections import defaultdict
import time
import warnings

warnings.filterwarnings("ignore")

MODEL_PATH = '/home/kbc/ips-security_capstone_projects/ai_ips_model.pkl'
INTERFACE = 'ens18'
ATTACKER_IP = '117.16.174.60'

print("[*] 시스템 부팅 중...")
try:
    rf_model = joblib.load(MODEL_PATH)
    print("✅ AI 모델 로딩 완료!")
except Exception as e:
    print(f"❌ 모델 로드 실패: {e}")
    exit()

login_fails = defaultdict(int)
last_log_time = defaultdict(float) # 💡 로그 출력 시간 기록용
TARGET_PORTS = [21, 22, 80, 3306, 5000]

def log_attack(attack_type):
    # 💡 3초 이내에 동일한 공격 로그가 또 들어오면 출력하지 않음
    current_time = time.time()
    if current_time - last_log_time[attack_type] < 3.0:
        return
    
    print(f"[🚨 AI 탐지] 공격 유형: {attack_type}")
    last_log_time[attack_type] = current_time

def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        if src_ip != ATTACKER_IP: return
        dst_port = packet[TCP].dport
        if dst_port not in TARGET_PORTS: return
        
        payload_str = ""
        is_post = False
        
        try:
            if Raw in packet:
                payload_str = packet[Raw].load.decode('utf-8', errors='ignore')
                if "POST" in payload_str: is_post = True
            
            if is_post: login_fails[src_ip] += 1
        except: pass
                
        # 1. SQL Injection 우선 판별
        is_sqli = bool(re.search(r"(' OR '1'='1|UNION SELECT|DROP TABLE|--|;)", payload_str, re.IGNORECASE))
        
        # 2. Brute Force 판별
        is_brute = (login_fails[src_ip] > 5)
        
        # 3. Port Scan 판별 (모델 활용)
        prediction = rf_model.predict(pd.DataFrame([{
            'dst_port': dst_port, 
            'special_char_count': len(re.findall(r"['\"=;\-]", payload_str)), 
            'login_fail_count': login_fails[src_ip], 
            'packet_length': len(packet)
        }]))[0]
        
        # 우선순위에 따른 로그 호출
        if is_brute: log_attack("Brute Force")
        elif is_sqli: log_attack("SQL Injection")
        elif prediction == 1: log_attack("Port Scan")

print(f"[*] 감시 시작: {INTERFACE}")
sniff(iface=INTERFACE, prn=process_packet, store=False)
