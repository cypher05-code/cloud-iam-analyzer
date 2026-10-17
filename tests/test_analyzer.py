import pandas as pd
import pytest

from analyzer import analyze_events, load_audit_logs


def test_load_audit_logs():
    """Check that sample audit logs load correctly."""
    df = load_audit_logs()

    assert not df.empty
    assert "event_name" in df.columns
    assert "user" in df.columns


def test_failed_login_is_detected():
    """A failed console login should receive a risk score."""
    df = pd.DataFrame(
        [
            {
                "event_name": "ConsoleLogin",
                "status": "Failure",
                "privileged": False,
            }
        ]
    )

    result = analyze_events(df)

    assert result.iloc[0]["risk_score"] == 20
    assert "Failed login attempt" in result.iloc[0]["findings"]


def test_access_key_creation_is_detected():
    """Access key creation should be flagged."""
    df = pd.DataFrame(
        [
            {
                "event_name": "CreateAccessKey",
                "status": "Success",
                "privileged": False,
            }
        ]
    )

    result = analyze_events(df)

    assert result.iloc[0]["risk_score"] == 30
    assert result.iloc[0]["severity"] == "Medium"


def test_iam_permission_change_is_high_risk():
    """A privileged IAM policy change should be high risk."""
    df = pd.DataFrame(
        [
            {
                "event_name": "PutUserPolicy",
                "status": "Success",
                "privileged": True,
            }
        ]
    )

    result = analyze_events(df)

    assert result.iloc[0]["risk_score"] == 50
    assert result.iloc[0]["severity"] == "High"


def test_normal_event_has_no_risk():
    """A normal event should not trigger any rules."""
    df = pd.DataFrame(
        [
            {
                "event_name": "GetObject",
                "status": "Success",
                "privileged": False,
            }
        ]
    )

    result = analyze_events(df)

    assert result.iloc[0]["risk_score"] == 0
    assert result.iloc[0]["severity"] == "Informational"


def test_risk_score_never_exceeds_100():
    """The risk score should be capped at 100."""
    df = pd.DataFrame(
        [
            {
                "event_name": "PutUserPolicy",
                "status": "Failure",
                "privileged": True,
            }
        ]
    )

    result = analyze_events(df)

    assert result.iloc[0]["risk_score"] <= 100


def test_invalid_json_structure_raises_error(tmp_path):
    """A JSON object instead of a list should be rejected."""
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text('{"event": "ConsoleLogin"}', encoding="utf-8")

    with pytest.raises(ValueError):
        load_audit_logs(invalid_file)
