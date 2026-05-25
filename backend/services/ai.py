from __future__ import annotations


BLOCKED_TOKENS = ("sudo", "bash", "sh ", "curl ", "wget", "python", ";", "&&", "||", "|", "`", "$(")


def classify_operator_message(message: str) -> dict:
    normalized = message.lower().replace("\n", " ").strip()
    compact = "".join(normalized.split())

    if not compact:
        return {"action": "reject", "reply": "요청 내용을 입력해 주세요."}

    if any(token in normalized or token in compact for token in BLOCKED_TOKENS):
        return {
            "action": "reject",
            "reply": "임의 명령어는 실행할 수 없습니다. 사전 정의된 안전 시나리오만 허용됩니다.",
        }

    if "summary" in compact or "요약" in compact:
        return {"action": "summary"}

    if "status" in compact or "상태" in compact or "ips" in compact or "wazuh" in compact:
        return {"action": "status"}

    if "event" in compact or "로그" in compact or "탐지" in compact:
        if "sql" in compact or "sqli" in compact or "인젝션" in compact:
            return {"action": "events", "attack_type": "SQL Injection"}
        if "brute" in compact or "브루트" in compact or "무차별" in compact:
            return {"action": "events", "attack_type": "Brute Force"}
        if "port" in compact or "scan" in compact or "포트" in compact or "스캔" in compact:
            return {"action": "events", "attack_type": "Port Scan"}
        return {"action": "events"}

    if "sql" in compact or "sqli" in compact or "인젝션" in compact:
        return {"action": "simulate", "scenario": "sqli"}
    if "brute" in compact or "브루트" in compact or "무차별" in compact:
        return {"action": "simulate", "scenario": "bruteforce"}
    if "port" in compact or "scan" in compact or "포트" in compact or "스캔" in compact:
        return {"action": "simulate", "scenario": "portscan"}
    if "공격" in compact or "random" in compact or "랜덤" in compact:
        return {"action": "simulate", "scenario": "random"}

    return {
        "action": "reject",
        "reply": "포트스캔, 브루트포스, SQL 인젝션 실행 또는 최근 로그/요약/상태 조회만 처리할 수 있습니다.",
    }
