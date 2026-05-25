from __future__ import annotations

import logging
import os
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

import requests
from requests.auth import HTTPBasicAuth


logger = logging.getLogger(__name__)
KST = timezone(timedelta(hours=9), "KST")

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

LAB_SIGNATURES = (
    "LAB Port scan detected",
    "LAB WEB brute force detected",
    "LAB SQL Injection detected",
)

LAB_RULE_ATTACK_TYPES = {
    "100001": "Port Scan",
    "100002": "Brute Force",
    "100003": "SQL Injection",
    "1000002": "Port Scan",
    "1000003": "Brute Force",
    "1000005": "SQL Injection",
}

NOISE_SIGNATURE_IDS = {"1000001", "2016149", "2016150", "2019102"}

NOISE_SIGNATURE_FRAGMENTS = (
    "ET INFO STUN",
    "STUN Binding",
    "Session Traversal Utilities for NAT",
    "SSDP",
    "LAB ICMP Ping Detected",
    "network_info",
)


class WazuhClient:
    def __init__(
        self,
        api_url: str,
        user: str,
        password: str,
        verify_ssl: bool,
        indexer: dict,
        demo_fallback: bool,
        default_lab_only: bool,
    ):
        self.api_url = api_url.rstrip("/") + "/"
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl
        self.indexer = indexer
        self.demo_fallback = demo_fallback
        self.default_lab_only = default_lab_only
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
            default_lab_only=_bool_env("WAZUH_DEFAULT_LAB_ONLY", True),
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
                "default_lab_only": self.default_lab_only,
            }
        except Exception as exc:
            return {
                "ok": bool(indexer_status.get("ok")),
                "source": "wazuh-indexer" if indexer_status.get("ok") else "unavailable",
                "error": str(exc),
                "indexer": indexer_status,
                "demo_fallback": self.demo_fallback,
                "default_lab_only": self.default_lab_only,
            }

    def recent_events(self, limit: int = 50, attack_type: str | None = None, lab_only: bool | None = None) -> list[dict]:
        if lab_only is None:
            lab_only = self.default_lab_only
        search_limit = max(limit, 1000) if lab_only else limit
        try:
            events = self._indexer_events(search_limit)
        except Exception as exc:
            logger.warning("Wazuh indexer event search failed: %s", exc)
            events = DEMO_EVENTS if self.demo_fallback else []

        if lab_only:
            events = [event for event in events if _is_lab_event(event)]

        if attack_type:
            events = [event for event in events if event.get("attack_type") == attack_type]
        return events[:limit]

    def summary(self, lab_only: bool | None = None) -> dict:
        events = self.recent_events(limit=50000, lab_only=lab_only)
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

    def timeline(self, lab_only: bool | None = None) -> list[dict]:
        now = datetime.now(KST)
        end_hour = now.replace(minute=0, second=0, microsecond=0)
        start_hour = end_hour - timedelta(hours=12)
        bucket_times = [start_hour + timedelta(hours=offset) for offset in range(13)]
        buckets = {hour.strftime("%H:00"): Counter() for hour in bucket_times}

        for event in self.recent_events(limit=50000, lab_only=lab_only):
            event_time = _parse_event_time(event.get("timestamp"))
            if not event_time:
                continue
            event_kst = event_time.astimezone(KST)
            if event_kst < start_hour or event_kst > now:
                continue

            label = event_kst.replace(minute=0, second=0, microsecond=0).strftime("%H:00")
            bucket = buckets.get(label)
            if bucket is None:
                continue

            attack_type = event.get("attack_type")
            if attack_type == "Port Scan":
                bucket["portscan"] += 1
            elif attack_type == "Brute Force":
                bucket["bruteforce"] += 1
            elif attack_type == "SQL Injection":
                bucket["sqli"] += 1

        return [
            {
                "time": hour.strftime("%H:00"),
                "portscan": buckets[hour.strftime("%H:00")]["portscan"],
                "bruteforce": buckets[hour.strftime("%H:00")]["bruteforce"],
                "sqli": buckets[hour.strftime("%H:00")]["sqli"],
            }
            for hour in bucket_times
        ]

    def blocked_ips(self, lab_only: bool | None = None) -> list[dict]:
        counter = Counter()
        for event in self.recent_events(limit=200, lab_only=lab_only):
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

        url = f"{self.indexer['url']}/{self.indexer['index']}/_search"
        events: list[dict] = []
        search_after = None
        batch_size = min(1000, max(1, limit))

        while len(events) < limit:
            query = {
                "size": min(batch_size, limit - len(events)),
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
            if search_after:
                query["search_after"] = search_after

            response = requests.post(
                url,
                json=query,
                auth=HTTPBasicAuth(self.indexer["user"], self.indexer["password"]),
                timeout=20,
                verify=self.indexer["verify_ssl"],
            )
            response.raise_for_status()
            hits = response.json().get("hits", {}).get("hits", [])
            if not hits:
                break

            events.extend(_normalize_event(hit) for hit in hits)
            search_after = hits[-1].get("sort")
            if not search_after or len(hits) < batch_size:
                break

        return events[:limit]

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
    full_log = str(source.get("full_log") or "")
    signature = alert.get("signature") or _suricata_signature(full_log) or rule.get("description") or full_log or "Unknown alert"
    signature_id = str(
        alert.get("signature_id")
        or _suricata_signature_id(data.get("id"))
        or _suricata_signature_id(full_log)
        or rule.get("id", "-")
    )
    attack_type = _attack_type(signature, rule.get("groups", []), signature_id)
    return {
        "id": hit.get("_id"),
        "timestamp": source.get("@timestamp", ""),
        "attack_type": attack_type,
        "src_ip": _first_value(source, data, "src_ip", "srcip", "src_ip_addr", "source.ip", "win.eventdata.ipAddress"),
        "dest_ip": _first_value(source, data, "dest_ip", "dst_ip", "destip", "dstip", "destination.ip"),
        "dest_port": str(_first_value(source, data, "dest_port", "dst_port", "destination.port")),
        "signature_id": signature_id,
        "signature": signature,
        "severity": alert.get("severity") or rule.get("level", 0),
        "action": _action(source, alert, rule),
        "agent": agent.get("name") or agent.get("id") or "-",
        "decoder": decoder.get("name") or "-",
        "location": source.get("location", "-"),
        "rule_groups": rule.get("groups", []),
    }


def _parse_event_time(value) -> datetime | None:
    if not value:
        return None

    raw = str(value).strip()
    try:
        if "T" in raw:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed

        parsed_time = datetime.strptime(raw[:8], "%H:%M:%S").time()
        return datetime.combine(datetime.now(KST).date(), parsed_time, tzinfo=KST)
    except ValueError:
        return None


def _is_lab_event(event: dict) -> bool:
    signature = str(event.get("signature", ""))
    signature_id = str(event.get("signature_id", ""))
    if signature_id in NOISE_SIGNATURE_IDS:
        return False
    return signature_id in LAB_RULE_ATTACK_TYPES or any(expected in signature for expected in LAB_SIGNATURES)


def _is_noise_event(event: dict) -> bool:
    signature = str(event.get("signature", ""))
    decoder = str(event.get("decoder", ""))
    signature_id = str(event.get("signature_id", ""))
    groups = event.get("rule_groups", [])
    group_text = " ".join(groups) if isinstance(groups, list) else str(groups or "")
    text = f"{signature} {decoder} {group_text}"
    return signature_id in NOISE_SIGNATURE_IDS or any(fragment in text for fragment in NOISE_SIGNATURE_FRAGMENTS)


def _suricata_signature_id(value: object) -> str | None:
    match = re.search(r"\b\d+:(\d+):\d+\b", str(value or ""))
    return match.group(1) if match else None


def _suricata_signature(full_log: str) -> str | None:
    match = re.search(r"\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(.+?)\s+\[\*\*\]", full_log)
    return match.group(1) if match else None


def _attack_type(signature: str, groups: list | str | None = None, signature_id: str | None = None) -> str:
    if signature_id in LAB_RULE_ATTACK_TYPES:
        return LAB_RULE_ATTACK_TYPES[signature_id]
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
