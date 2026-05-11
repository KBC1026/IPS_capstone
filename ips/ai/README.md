# AI Traffic Detection

## 개요
이 모듈은 Suricata의 `eve.json` 로그를 읽어서 이상 탐지와 트래픽 유형 분류를 수행합니다.
GitHub 참고 저장소 `KBC1026/IPS_capstone`의 `캡스톤_AI.ipynb` 구조를 로컬 실습 환경에 맞게 반영했습니다.

## 사용 모델
- `anomaly_detector.py`: Isolation Forest 기반 비지도 이상 탐지
- `traffic_classifier.py`: Random Forest 기반 지도 학습 분류

## 입력 데이터
- `/var/log/suricata/eve.json`
- Kali 공격 로그 파일
  - `brute_force*.log`
  - `port_scan*.log`
  - `sql_injection*.log`

## 주요 기능
- Suricata 로그 파싱
- 주요 네트워크 특징값 추출
- 정상 / 이상 트래픽 분류
- 정상 / 포트스캔 / SQL Injection / 브루트포스 4분류
- 결과를 CSV 파일로 저장

## 추출하는 주요 Feature
- dest_port
- proto_num
- event_type_num
- alert severity
- flow packet 수
- flow byte 수
- SQL 특수문자 개수
- 로그인 실패 횟수 추정값

## 실행 방법

가상환경 생성 및 활성화:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

비지도 이상 탐지:
```bash
python anomaly_detector.py
```

지도 학습 모델 학습:
```bash
python traffic_classifier.py train \
  --eve /var/log/suricata/eve.json \
  --kali-log ../../kali/attack.log
```

학습된 모델로 예측:
```bash
python traffic_classifier.py predict \
  --eve /var/log/suricata/eve.json
```

출력 파일:
```text
output/anomalies.csv
output/traffic_classifier.pkl
output/traffic_classifier_report.txt
output/traffic_predictions.csv
```

## 운영 주의사항

자동 차단에 바로 연결하지 말고 `traffic_predictions.csv`의 `predicted_name`과 `confidence`를 먼저 검토하세요.
실습망에서는 `confidence >= 0.8` 이상인 반복 공격만 차단 후보로 쓰는 편이 안전합니다.
