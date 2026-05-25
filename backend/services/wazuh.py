from __future__ import annotations

import logging
import os
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urljoin

import requests
from requests.auth import HTTPBasicAuth


logger = logging.getLogger(__name__)

DEMO_EVENTS = [
    {
        "id": "demo-1001",
        "timestamp": "14:03:22",
        "attack_type": "Port Scan",
        "src_ip": "192.168.2.10",
        "dest_ip": "192.168.2.100",
        "dest_port": "22-8080",
        "signature_id": "100001",
        "signature": "LAB Port scan detected",
        "severity": 8,
        "action": "BLOCKED",
    },
    {
        "id": "demo-1002",
        "timestamp": "14:01:48",
        "attack_type": "SQL Injection",
        "src_ip": "192.168.2.10",
        "dest_ip": "192.168.2.100",
        "dest_port": "80",
        "signature_id": "100003",
        "signature": "LAB SQL Injection detected",
        "severity": 7,
        "action": "ALERT",
    },
    {
        "id": "demo-1003",
        "timestamp": "13:58:09",
        "attack_type": "Brute Force",
        "src_ip": "192.168.2.10",
        "dest_ip": "192.168.2.100",
        "dest_port": "22",
        "signature_id": "100002",
        "signature": "LAB WEB brute force detected",
        "severity": 9,
        "action": "BLOCKED",
    },
]


class WazuhClient:
    def __init__(self, api_url: str, user: str, password: str, verify_ssl: bool, indexer: dict, demo_fallback: bool):
        self.api_url = api_url.rstrip("/") + "/"
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl
        self.indexer = indexer
        self.demo_fallback = demo_fallback
        self._token: str | None = None

    @classmethod
    def from_env(cls) -> "WazuhClient":
        base = os.getenv("WAZUH_URL", "https://127.0.0.1").rstrip("/")
        port = os.getenv("WAZUH_API_PORT", "55000")
        return cls(
            api_url=f"{base}:{port}",
            user=os.getenv("WAZUH_USER", "admin"),
            password=os.getenv("WAZUH_PASSWORD", ""),
            verify_ssl=_bool_env("WAZUH_VERIFY_SSL", False),
            indexer={
                "url": os.getenv("WAZUH_INDEXER_URL", "").rstrip("/"),
                "user": os.getenv("WAZUH_INDEXER_USER", ""),
                "password": os.getenv("WAZUH_INDEXER_PASSWORD", ""),
                "verify_ssl": _bool_env("WAZUH_INDEXER_VERIFY_SSL", False),
                "index": os.getenv("WAZUH_ALERT_INDEX", "wazuh-alerts-*"),
                "time_range": os.getenv("WAZUH_ALERT_TIME_RANGE", "now-24h"),
            },
            demo_fallback=_bool_env("WAZUH_DEMO_FALLBACK", False),
        )

    def health(self) -> dict:
        indexer_status = self._indexer_health()
        try:
            agents = self._api_get("agents", params={"limit": 1})
            return {
                "ok": True,
                "source": "wazuh-api",
                "agents_seen": agents.get("data", {}).get("total_affected_items", 0),
                "indexer": indexer_status,
                "demo_fallback": self.demo_fallback,
            }
        except Exception as exc:
            return {
                "ok": bool(indexer_status.get("ok")),
                "source": "wazuh-indexer" if indexer_status.get("ok") else "unavailable",
                "error": str(exc),
                "indexer": indexer_status,
                "demo_fallback": self.demo_fallback,
            }

    def recent_events(self, limit: int = 50, attack_type: str | None = None) -> list[dict]:
        try:
            events = self._indexer_events(limit)
        except Exception as exc:
            logger.warning("Wazuh indexer event search failed: %s", exc)
            events = DEMO_EVENTS if self.demo_fallback else []

        if attack_type:
            events = [event for event in events if event.get("attack_type") == attack_type]
        return events[:limit]

    def summary(self) -> dict:
        events = self.recent_events(limit=200)
        counts = Counter(event.get("attack_type", "Unknown") for event in events)
        blocked = {event.get("src_ip") for event in events if event.get("action") == "BLOCKED" and event.get("src_ip")}
        return {
            "total": len(events),
            "portscan": counts.get("Port Scan", 0),
            "bruteforce": counts.get("Brute Force", 0),
            "sqli": counts.get("SQL Injection", 0),
            "blocked": len(blocked),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    def timeline(self) -> list[dict]:
        buckets: dict[str, Counter] = {}
        for event in self.recent_events(limit=200):
            label = str(event.get("timestamp", ""))[11:16] if "T" in str(event.get("timestamp", "")) else str(event.get("timestamp", ""))[:5]
            label = label or "now"
            bucket = buckets.setdefault(label, Counter())
            attack_type = event.get("attack_type")
            if attack_type == "Port Scan":
                bucket["portscan"] += 1
            elif attack_type == "Brute Force":
                bucket["bruteforce"] += 1
            elif attack_type == "SQL Injection":
                bucket["sqli"] += 1
        return [{"time": key, **value} for key, value in sorted(buckets.items())][-12:]

    def blocked_ips(self) -> list[dict]:
        counter = Counter()
        for event in self.recent_events(limit=200):
            if event.get("action") == "BLOCKED" and event.get("src_ip"):
                counter[event["src_ip"]] += 1
        return [{"ip": ip, "events": count} for ip, count in counter.most_common(20)]

    def _api_get(self, path: str, params: dict | None = None) -> dict:
        token = self._get_token()
        response = requests.get(
            urljoin(self.api_url, path),
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=10,
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        return response.json()

    def _get_token(self) -> str:
        if self._token:
            return self._token
        response = requests.get(
            urljoin(self.api_url, "security/user/authenticate"),
            auth=HTTPBasicAuth(self.user, self.password),
            timeout=10,
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        self._token = response.json()["data"]["token"]
        return self._token

    def _indexer_events(self, limit: int) -> list[dict]:
        if not self.indexer["url"]:
            raise RuntimeError("WAZUH_INDEXER_URL is not configured")

        query = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "track_total_hits": False,
            "query": {
                "bool": {
                    "filter": [
                        {"exists": {"field": "rule.id"}},
                        {"range": {"@timestamp": {"gte": self.indexer["time_range"]}}},
                    ]
                }
            },
        }
        url = f"{self.indexer['url']}/{self.indexer['index']}/_search"
        response = requests.post(
            url,
            json=query,
            auth=HTTPBasicAuth(self.indexer["user"], self.indexer["password"]),
            timeout=10,
            verify=self.indexer["verify_ssl"],
        )
        response.raise_for_status()
        hits = response.json().get("hits", {}).get("hits", [])
        return [_normalize_event(hit) for hit in hits]

    def _indexer_health(self) -> dict:
        if not self.indexer["url"]:
            return {"ok": False, "source": "wazuh-indexer", "error": "WAZUH_INDEXER_URL is not configured"}
        try:
            response = requests.get(
                f"{self.indexer['url']}/_cluster/health",
                auth=HTTPBasicAuth(self.indexer["user"], self.indexer["password"]),
                timeout=5,
                verify=self.indexer["verify_ssl"],
            )
            response.raise_for_status()
            payload = response.json()
            return {"ok": True, "source": "wazuh-indexer", "status": payload.get("status")}
        except Exception as exc:
            return {"ok": False, "source": "wazuh-indexer", "error": str(exc)}


def _normalize_event(hit: dict) -> dict:
    source = hit.get("_source", {})
    data = source.get("data", {})
    alert = data.get("alert", {})
    rule = source.get("rule", {})
    decoder = source.get("decoder", {})
    agent = source.get("agent", {})
    signature = alert.get("signature") or rule.get("description") or source.get("full_log") or "Unknown alert"
    attack_type = _attack_type(signature, rule.get("groups", []))
    return {
        "id": hit.get("_id"),
        "timestamp": source.get("@timestamp", ""),
        "attack_type": attack_type,
        "src_ip": _first_value(source, data, "src_ip", "srcip", "src_ip_addr", "source.ip", "win.eventdata.ipAddress"),
        "dest_ip": _first_value(source, data, "dest_ip", "dst_ip", "destip", "dstip", "destination.ip"),
        "dest_port": str(_first_value(source, data, "dest_port", "dst_port", "destination.port")),
        "signature_id": str(alert.get("signature_id") or rule.get("id", "-")),
        "signature": signature,
        "severity": alert.get("severity") or rule.get("level", 0),
        "action": _action(source, alert, rule),
        "agent": agent.get("name") or agent.get("id") or "-",
        "decoder": decoder.get("name") or "-",
        "location": source.get("location", "-"),
        "rule_groups": rule.get("groups", []),
    }


def _attack_type(signature: str, groups: list | str | None = None) -> str:
    group_text = " ".join(groups) if isinstance(groups, list) else str(groups or "")
    value = f"{signature} {group_text}".lower()
    if "sql" in value or "injection" in value:
        return "SQL Injection"
    if "brute" in value or "login" in value:
        return "Brute Force"
    if "scan" in value or "nmap" in value:
        return "Port Scan"
    return "Other"


def _action(source: dict, alert: dict, rule: dict) -> str:
    action = str(alert.get("action") or source.get("action") or "").upper()
    if "BLOCK" in action or "DROP" in action:
        return "BLOCKED"
    if any(group in {"firewall", "iptables"} for group in rule.get("groups", [])):
        return "BLOCKED"
    return "ALERT"


def _first_value(source: dict, data: dict, *keys: str) -> str:
    for key in keys:
        value = _nested_get(data, key)
        if value not in {None, ""}:
            return value
        value = _nested_get(source, key)
        if value not in {None, ""}:
            return value
    return "-"


def _nested_get(payload: dict, dotted_key: str):
    current = payload
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}
