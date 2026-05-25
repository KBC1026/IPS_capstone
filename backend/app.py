from __future__ import annotations

import os
import random
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

from services.ai import classify_operator_message
from services.kali import KaliRunner
from services.wazuh import WazuhClient


def create_app() -> Flask:
    load_dotenv()

    app = Flask(__name__)
    allowed_origins = [
        origin.strip()
        for origin in os.getenv("ALLOWED_ORIGINS", "https://chanxai.com").split(",")
        if origin.strip()
    ]
    CORS(app, resources={r"/api/*": {"origins": allowed_origins}})

    wazuh = WazuhClient.from_env()
    kali = KaliRunner.from_env()

    @app.get("/api/health")
    def health():
        wazuh_status = wazuh.health()
        return jsonify(
            {
                "ok": True,
                "service": "chanxai-api",
                "time": datetime.now(timezone.utc).isoformat(),
                "wazuh": wazuh_status,
            }
        )

    @app.get("/api/security/events")
    def security_events():
        limit = _int_arg("limit", 50, minimum=1, maximum=200)
        attack_type = request.args.get("attack_type")
        lab_only = _bool_arg("lab_only", wazuh.default_lab_only)
        return jsonify({"events": wazuh.recent_events(limit=limit, attack_type=attack_type, lab_only=lab_only)})

    @app.get("/api/security/summary")
    def security_summary():
        lab_only = _bool_arg("lab_only", wazuh.default_lab_only)
        return jsonify(wazuh.summary(lab_only=lab_only))

    @app.get("/api/security/timeline")
    def security_timeline():
        lab_only = _bool_arg("lab_only", wazuh.default_lab_only)
        return jsonify({"timeline": wazuh.timeline(lab_only=lab_only)})

    @app.get("/api/security/blocked-ips")
    def blocked_ips():
        lab_only = _bool_arg("lab_only", wazuh.default_lab_only)
        return jsonify({"blocked_ips": wazuh.blocked_ips(lab_only=lab_only)})

    @app.post("/api/simulation/<scenario>")
    def run_simulation(scenario: str):
        if scenario == "random":
            scenario = random.choice(["portscan", "bruteforce", "sqli"])
        result = kali.run(scenario)
        status = 202 if result["accepted"] else 400
        return jsonify(result), status

    @app.post("/api/ai/chat")
    def ai_chat():
        payload = request.get_json(silent=True) or {}
        message = str(payload.get("message", "")).strip()
        intent = classify_operator_message(message)

        if intent["action"] == "reject":
            return jsonify({"intent": intent, "reply": intent["reply"]}), 400

        if intent["action"] == "summary":
            summary = wazuh.summary()
            reply = (
                f"최근 이벤트 {summary['total']}건입니다. "
                f"Port Scan {summary['portscan']}건, Brute Force {summary['bruteforce']}건, "
                f"SQL Injection {summary['sqli']}건, 차단 IP {summary['blocked']}개입니다."
            )
            return jsonify({"intent": intent, "reply": reply, "summary": summary})

        if intent["action"] == "events":
            events = wazuh.recent_events(limit=10, attack_type=intent.get("attack_type"))
            return jsonify({"intent": intent, "reply": f"최근 이벤트 {len(events)}건을 조회했습니다.", "events": events})

        if intent["action"] == "status":
            return jsonify({"intent": intent, "reply": "Wazuh API 상태를 조회했습니다.", "status": wazuh.health()})

        if intent["action"] == "simulate":
            result = kali.run(intent["scenario"])
            status = 202 if result["accepted"] else 400
            return jsonify({"intent": intent, "reply": result["message"], "simulation": result}), status

        return jsonify({"intent": intent, "reply": "요청을 처리할 수 없습니다."}), 400

    return app


def _int_arg(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def _bool_arg(name: str, default: bool) -> bool:
    value = request.args.get(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


if __name__ == "__main__":
    create_app().run(
        host=os.getenv("API_BIND_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", "8000")),
    )
