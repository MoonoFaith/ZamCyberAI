from threat_analysis import analyze_submission


def test_safe_message_has_low_risk():
    assessment = analyze_submission("Can you explain how two-factor authentication works?")
    assert assessment["verdict"] == "safe"
    assert assessment["risk_score"] == 0


def test_phishing_link_and_urgency_are_flagged():
    assessment = analyze_submission(
        "URGENT: Your account is suspended. Verify your password at http://paypal-secure-login.top/verify"
    )
    assert assessment["verdict"] in {"scam", "malicious"}
    assert assessment["risk_score"] >= 40
    assert assessment["urls"]


def test_email_authentication_failure_is_flagged():
    assessment = analyze_submission(
        "From: Bank <help@bank.example>\n"
        "Reply-To: attacker@evil.example\n"
        "Authentication-Results: mx.example; spf=fail; dmarc=fail\n\n"
        "Verify your account immediately"
    )
    assert assessment["verdict"] in {"scam", "malicious"}
