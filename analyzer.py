import json
from pathlib import Path

import pandas as pd

DATA_FILE = Path(__file__).parent / "sample_data" / "audit_logs.json"


def load_audit_logs(file_path=DATA_FILE):
    """Load audit events from a JSON file."""
    with open(file_path, "r", encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("Audit log data must be a JSON list.")

    if not all(isinstance(event, dict) for event in events):
        raise ValueError("Every audit event must be a JSON object.")

    return pd.DataFrame(events)


def analyze_events(df):
    """Flag potentially suspicious cloud audit events."""
    results = df.copy()

    results["risk_score"] = 0
    results["findings"] = ""

    for index, event in results.iterrows():
        findings = []
        score = 0

        # Rule 1: Failed login attempts
        if (
            event.get("event_name") == "ConsoleLogin"
            and event.get("status") == "Failure"
        ):
            score += 20
            findings.append("Failed login attempt")

        # Rule 2: Creation of access keys
        if event.get("event_name") == "CreateAccessKey":
            score += 30
            findings.append("Access key created")

        # Rule 3: Changes to user permissions
        if event.get("event_name") in {
            "PutUserPolicy",
            "AttachUserPolicy",
            "AttachRolePolicy",
        }:
            score += 40
            findings.append("IAM permission change")

        # Rule 4: Privileged activity
        if event.get("privileged") is True:
            score += 10
            findings.append("Privileged account activity")

        results.at[index, "risk_score"] = min(score, 100)
        results.at[index, "findings"] = (
            "; ".join(findings) if findings else "No rule triggered"
        )

    def get_severity(score):
        if score >= 50:
            return "High"
        if score >= 30:
            return "Medium"
        if score > 0:
            return "Low"
        return "Informational"

    results["severity"] = results["risk_score"].apply(get_severity)

    return results


def main():
    events = load_audit_logs()
    analyzed = analyze_events(events)

    columns = [
        "event_id",
        "user",
        "event_name",
        "risk_score",
        "severity",
        "findings",
    ]

    print(analyzed[columns].to_string(index=False))


if __name__ == "__main__":
    main()
