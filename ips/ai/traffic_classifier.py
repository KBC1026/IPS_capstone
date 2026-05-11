import argparse
import json
import os
import pickle
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
DEFAULT_MODEL_PATH = os.path.join(OUTPUT_DIR, "traffic_classifier.pkl")
DEFAULT_REPORT_PATH = os.path.join(OUTPUT_DIR, "traffic_classifier_report.txt")
DEFAULT_PREDICTION_CSV = os.path.join(OUTPUT_DIR, "traffic_predictions.csv")

LABELS = {
    0: "normal",
    1: "port_scan",
    2: "sqli",
    3: "brute_force",
}

FEATURE_COLUMNS = [
    "dest_port",
    "proto_num",
    "event_type_num",
    "severity",
    "packet_length",
    "pkts_toserver",
    "bytes_toserver",
    "special_char_count",
    "login_fail_count",
]

SQL_SPECIAL_CHARS = "'\"#-/*=();%"


@dataclass
class Sample:
    source: str
    timestamp: str
    src_ip: str
    dest_ip: str
    signature: str
    features: Dict[str, int]
    label: Optional[int] = None


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_get(data: Dict[str, Any], keys: Iterable[str], default: Any = 0) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


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


def count_special_chars(value: str) -> int:
    return sum(1 for char in str(value) if char in SQL_SPECIAL_CHARS)


def infer_label_from_text(text: str) -> Optional[int]:
    lowered = text.lower()
    if any(token in lowered for token in ["port scan", "port_scan", "nmap"]):
        return 1
    if any(token in lowered for token in ["sql injection", "sqli", "union select", " or ", "drop table"]):
        return 2
    if any(token in lowered for token in ["brute force", "brute_force", "credential stuffing", "bf_"]):
        return 3
    return None


def eve_log_to_sample(log: Dict[str, Any], source: str) -> Sample:
    event_type = str(log.get("event_type", ""))
    proto = str(log.get("proto", ""))
    dest_port = safe_int(log.get("dest_port", 0))
    severity = safe_int(safe_get(log, ["alert", "severity"], 0))
    signature = str(safe_get(log, ["alert", "signature"], ""))

    http_text = " ".join(
        str(value)
        for value in [
            safe_get(log, ["http", "url"], ""),
            safe_get(log, ["http", "hostname"], ""),
            safe_get(log, ["http", "http_method"], ""),
            signature,
        ]
        if value
    )

    pkts_toserver = safe_int(safe_get(log, ["flow", "pkts_toserver"], 0))
    bytes_toserver = safe_int(safe_get(log, ["flow", "bytes_toserver"], 0))
    bytes_toclient = safe_int(safe_get(log, ["flow", "bytes_toclient"], 0))
    packet_length = bytes_toserver + bytes_toclient

    label = infer_label_from_text(signature)
    if label is None and event_type in {"flow", "http", "dns", "tls"}:
        label = 0

    login_fail_count = 0
    if label == 3:
        login_fail_count = 10

    return Sample(
        source=source,
        timestamp=str(log.get("timestamp", "")),
        src_ip=str(log.get("src_ip", "")),
        dest_ip=str(log.get("dest_ip", "")),
        signature=signature,
        label=label,
        features={
            "dest_port": dest_port,
            "proto_num": proto_to_int(proto),
            "event_type_num": event_type_to_int(event_type),
            "severity": severity,
            "packet_length": packet_length,
            "pkts_toserver": pkts_toserver,
            "bytes_toserver": bytes_toserver,
            "special_char_count": count_special_chars(http_text),
            "login_fail_count": login_fail_count,
        },
    )


def load_eve_samples(path: str, require_labels: bool) -> List[Sample]:
    samples: List[Sample] = []
    if not path or not os.path.exists(path):
        return samples

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                log = json.loads(line)
            except json.JSONDecodeError:
                continue
            sample = eve_log_to_sample(log, path)
            if sample.label is not None or not require_labels:
                samples.append(sample)

    return samples


def kali_line_to_sample(line: str, source: str) -> Optional[Sample]:
    label = infer_label_from_text(line)
    if label is None:
        return None

    timestamp = line.split("|", 1)[0].strip()
    port_match = re.search(r"(?:port|dst_port|dest_port)=(\d+)", line)
    status_match = re.search(r"status=(\d+)", line)
    attempt_match = re.search(r"attempt=(\d+)", line)
    target_match = re.search(r"target=([\d.]+)", line)
    query_match = re.search(r"(?:query|user|username)=([^|]+)", line)

    dest_port = safe_int(port_match.group(1), 5000) if port_match else 5000
    status_code = safe_int(status_match.group(1), 0) if status_match else 0
    login_fail_count = safe_int(attempt_match.group(1), 0) if attempt_match else 0
    payload = query_match.group(1).strip() if query_match else line

    if label == 1 and not port_match:
        dest_port = 0
    if label == 3 and login_fail_count == 0:
        login_fail_count = 10

    return Sample(
        source=source,
        timestamp=timestamp,
        src_ip="",
        dest_ip=target_match.group(1) if target_match else "192.168.2.100",
        signature=line.strip(),
        label=label,
        features={
            "dest_port": dest_port,
            "proto_num": 1,
            "event_type_num": 1,
            "severity": 2 if status_code in {400, 401, 403, 423, 429} else 1,
            "packet_length": max(len(line), 40),
            "pkts_toserver": 1,
            "bytes_toserver": max(len(line), 40),
            "special_char_count": count_special_chars(payload),
            "login_fail_count": login_fail_count,
        },
    )


def load_kali_samples(paths: List[str]) -> List[Sample]:
    samples: List[Sample] = []
    for path in paths:
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as file:
            for line in file:
                sample = kali_line_to_sample(line, path)
                if sample:
                    samples.append(sample)
    return samples


def samples_to_dataframe(samples: List[Sample]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for sample in samples:
        row: Dict[str, Any] = {
            "source": sample.source,
            "timestamp": sample.timestamp,
            "src_ip": sample.src_ip,
            "dest_ip": sample.dest_ip,
            "signature": sample.signature,
        }
        row.update(sample.features)
        if sample.label is not None:
            row["label"] = sample.label
            row["label_name"] = LABELS[sample.label]
        rows.append(row)
    return pd.DataFrame(rows)


def train_model(df: pd.DataFrame) -> Tuple[RandomForestClassifier, str]:
    labeled_df = df.dropna(subset=["label"]).copy()
    labeled_df["label"] = labeled_df["label"].astype(int)

    label_count = labeled_df["label"].nunique()
    if label_count < 2:
        raise ValueError("At least two labeled traffic classes are required for supervised training.")

    x_data = labeled_df[FEATURE_COLUMNS].fillna(0)
    y_data = labeled_df["label"]

    stratify = y_data if y_data.value_counts().min() >= 2 else None
    x_train, x_test, y_train, y_test = train_test_split(
        x_data,
        y_data,
        test_size=0.2,
        random_state=42,
        stratify=stratify,
    )

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        class_weight="balanced",
        random_state=42,
    )
    model.fit(x_train, y_train)

    predicted = model.predict(x_test)
    labels = sorted(y_data.unique())
    target_names = [LABELS[label] for label in labels]
    report = classification_report(
        y_test,
        predicted,
        labels=labels,
        target_names=target_names,
        zero_division=0,
    )
    matrix = confusion_matrix(y_test, predicted, labels=labels)
    report = report + "\nConfusion matrix labels: " + ", ".join(target_names) + "\n"
    report = report + str(matrix) + "\n"

    return model, report


def save_model(model: RandomForestClassifier, model_path: str, report: str, report_path: str) -> None:
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    with open(model_path, "wb") as file:
        pickle.dump({"model": model, "features": FEATURE_COLUMNS, "labels": LABELS}, file)
    with open(report_path, "w", encoding="utf-8") as file:
        file.write(report)


def predict_samples(model_path: str, samples: List[Sample], output_csv: str) -> pd.DataFrame:
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")
    with open(model_path, "rb") as file:
        payload = pickle.load(file)
    model = payload["model"]
    features = payload["features"]

    df = samples_to_dataframe(samples)
    if df.empty:
        raise ValueError("No samples found for prediction.")

    probabilities = model.predict_proba(df[features].fillna(0))
    predictions = model.predict(df[features].fillna(0))

    df["predicted_label"] = predictions
    df["predicted_name"] = [LABELS[int(label)] for label in predictions]
    df["confidence"] = probabilities.max(axis=1)

    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False)
    return df


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train or run a traffic classifier for the IPS lab.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    train_parser = subparsers.add_parser("train", help="Train a supervised traffic classifier.")
    train_parser.add_argument("--eve", default="/var/log/suricata/eve.json", help="Path to Suricata eve.json.")
    train_parser.add_argument("--kali-log", action="append", default=[], help="Path to a Kali attack log file.")
    train_parser.add_argument("--model-out", default=DEFAULT_MODEL_PATH, help="Output model path.")
    train_parser.add_argument("--report-out", default=DEFAULT_REPORT_PATH, help="Output training report path.")

    predict_parser = subparsers.add_parser("predict", help="Classify traffic samples with a trained model.")
    predict_parser.add_argument("--eve", default="/var/log/suricata/eve.json", help="Path to Suricata eve.json.")
    predict_parser.add_argument("--kali-log", action="append", default=[], help="Optional Kali log file to classify.")
    predict_parser.add_argument("--model", default=DEFAULT_MODEL_PATH, help="Trained model path.")
    predict_parser.add_argument("--output", default=DEFAULT_PREDICTION_CSV, help="Prediction CSV output path.")

    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.command == "train":
        samples = load_eve_samples(args.eve, require_labels=True)
        samples.extend(load_kali_samples(args.kali_log))
        df = samples_to_dataframe(samples)
        if df.empty:
            raise ValueError("No labeled samples found. Provide eve.json alerts or Kali attack logs.")

        model, report = train_model(df)
        save_model(model, args.model_out, report, args.report_out)
        print(f"[+] Trained samples: {len(df)}")
        print(f"[+] Model saved to: {args.model_out}")
        print(f"[+] Report saved to: {args.report_out}")
        print(report)

    if args.command == "predict":
        samples = load_eve_samples(args.eve, require_labels=False)
        samples.extend(load_kali_samples(args.kali_log))
        df = predict_samples(args.model, samples, args.output)
        print(f"[+] Predicted samples: {len(df)}")
        print(f"[+] Saved predictions to: {args.output}")
        print(df[["timestamp", "src_ip", "dest_ip", "predicted_name", "confidence", "signature"]].head(20).to_string(index=False))


if __name__ == "__main__":
    main()
