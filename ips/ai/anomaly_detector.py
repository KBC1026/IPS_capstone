import json
import os
import ipaddress
from typing import Any, Dict, List, Optional

import pandas as pd
from sklearn.ensemble import IsolationForest


EVE_LOG_PATH = "/var/log/suricata/eve.json"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "anomalies.csv")


def ip_to_int(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip))
    except Exception:
        return 0


def proto_to_int(proto: str) -> int:
    mapping = {
        "TCP": 1,
        "UDP": 2,
        "ICMP": 3,
        "HTTP": 4,
        "DNS": 5,
        "TLS": 6,
    }
    return mapping.get(str(proto).upper(), 0)


def event_type_to_int(event_type: str) -> int:
    mapping = {
        "alert": 1,
        "flow": 2,
        "http": 3,
        "dns": 4,
        "tls": 5,
        "ssh": 6,
        "fileinfo": 7,
    }
    return mapping.get(str(event_type).lower(), 0)


def safe_get(data: Dict[str, Any], keys: List[str], default: Any = 0) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def extract_features(line: str) -> Optional[Dict[str, Any]]:
    try:
        log = json.loads(line)
    except json.JSONDecodeError:
        return None

    src_ip = log.get("src_ip", "")
    dest_ip = log.get("dest_ip", "")
    dest_port = log.get("dest_port", 0)
    proto = log.get("proto", "")
    event_type = log.get("event_type", "")
    flow_id = log.get("flow_id", 0)

    severity = safe_get(log, ["alert", "severity"], 0)
    signature = safe_get(log, ["alert", "signature"], "")

    pkts_toserver = safe_get(log, ["flow", "pkts_toserver"], 0)
    pkts_toclient = safe_get(log, ["flow", "pkts_toclient"], 0)
    bytes_toserver = safe_get(log, ["flow", "bytes_toserver"], 0)
    bytes_toclient = safe_get(log, ["flow", "bytes_toclient"], 0)

    return {
        "timestamp": log.get("timestamp", ""),
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "dest_port": dest_port if isinstance(dest_port, int) else 0,
        "proto": proto,
        "event_type": event_type,
        "flow_id": flow_id if isinstance(flow_id, int) else 0,
        "severity": severity if isinstance(severity, int) else 0,
        "signature": signature,
        "pkts_toserver": pkts_toserver if isinstance(pkts_toserver, int) else 0,
        "pkts_toclient": pkts_toclient if isinstance(pkts_toclient, int) else 0,
        "bytes_toserver": bytes_toserver if isinstance(bytes_toserver, int) else 0,
        "bytes_toclient": bytes_toclient if isinstance(bytes_toclient, int) else 0,
        "src_ip_num": ip_to_int(src_ip),
        "dest_ip_num": ip_to_int(dest_ip),
        "proto_num": proto_to_int(proto),
        "event_type_num": event_type_to_int(event_type),
    }


def load_logs(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Suricata log file not found: {path}")

    rows: List[Dict[str, Any]] = []

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            row = extract_features(line)
            if row is not None:
                rows.append(row)

    if not rows:
        raise ValueError("No valid log entries found in eve.json")

    return pd.DataFrame(rows)


def detect_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    feature_columns = [
        "src_ip_num",
        "dest_ip_num",
        "dest_port",
        "proto_num",
        "event_type_num",
        "severity",
        "pkts_toserver",
        "pkts_toclient",
        "bytes_toserver",
        "bytes_toclient",
    ]

    x_data = df[feature_columns].fillna(0)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
    )

    df["prediction"] = model.fit_predict(x_data)
    df["anomaly_score"] = model.decision_function(x_data)
    df["label"] = df["prediction"].apply(lambda x: "anomaly" if x == -1 else "normal")

    return df


def save_results(df: pd.DataFrame, output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    columns_to_save = [
        "timestamp",
        "src_ip",
        "dest_ip",
        "dest_port",
        "proto",
        "event_type",
        "severity",
        "signature",
        "pkts_toserver",
        "pkts_toclient",
        "bytes_toserver",
        "bytes_toclient",
        "anomaly_score",
        "label",
    ]

    df[columns_to_save].to_csv(output_path, index=False)


def main() -> None:
    print(f"[+] Loading logs from: {EVE_LOG_PATH}")
    df = load_logs(EVE_LOG_PATH)

    print(f"[+] Loaded {len(df)} entries")
    df = detect_anomalies(df)

    anomaly_df = df[df["label"] == "anomaly"]
    print(f"[+] Detected {len(anomaly_df)} anomalies")

    save_results(df, OUTPUT_CSV)
    print(f"[+] Saved results to: {OUTPUT_CSV}")

    if not anomaly_df.empty:
        print("\n[!] Top anomalies:")
        print(
            anomaly_df[
                [
                    "timestamp",
                    "src_ip",
                    "dest_ip",
                    "dest_port",
                    "proto",
                    "event_type",
                    "severity",
                    "signature",
                    "anomaly_score",
                ]
            ].head(10).to_string(index=False)
        )


if __name__ == "__main__":
    main()
