"""Safe, local first-pass analysis for pasted messages, URLs, and email headers.

This module deliberately does not open submitted URLs or attachments.  It is a
fast screening layer; a production deployment can add reputation and sandbox
providers behind this interface.
"""

from __future__ import annotations

import ipaddress
import re
from email import policy
from email.utils import parseaddr
from email.parser import Parser
from urllib.parse import urlparse

URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "click", "country", "gq", "tk", "work", "rest", "fit"}
BRANDS = ("paypal", "microsoft", "google", "apple", "amazon", "facebook", "whatsapp", "netflix", "airtel", "mtn", "zanaco")
URGENCY_TERMS = ("urgent", "immediately", "act now", "final warning", "within 24 hours", "account suspended", "account locked")
CREDENTIAL_TERMS = ("verify your account", "confirm your password", "login to", "sign in to", "reset your password", "one-time password", "otp", "security code")
PAYMENT_TERMS = ("gift card", "bitcoin", "crypto", "wire transfer", "mobile money", "send money", "payment required")
RISKY_EXTENSIONS = (".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".iso", ".zip", ".rar")


def _add(reasons: list[str], score: int, reason: str, points: int) -> int:
    reasons.append(reason)
    return score + points


def _extract_domain(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return (parsed.hostname or "").lower().rstrip(".")


def _analyse_url(url: str, reasons: list[str], score: int) -> int:
    clean_url = url.rstrip(".,;:!?)]}\"")
    parsed = urlparse(clean_url if "://" in clean_url else f"https://{clean_url}")
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()

    if not host:
        return _add(reasons, score, "The link is malformed.", 25)
    if "@" in parsed.netloc:
        score = _add(reasons, score, "The link uses an @ symbol, which can conceal its real destination.", 25)
    if host.startswith("xn--") or ".xn--" in host:
        score = _add(reasons, score, "The link uses an internationalized domain that may imitate another site.", 25)
    try:
        ipaddress.ip_address(host)
        score = _add(reasons, score, "The link uses a raw IP address instead of a recognizable domain.", 20)
    except ValueError:
        pass
    if host in SHORTENERS or any(host.endswith("." + item) for item in SHORTENERS):
        score = _add(reasons, score, "The link is shortened, hiding its final destination.", 15)
    if host.split(".")[-1] in SUSPICIOUS_TLDS:
        score = _add(reasons, score, "The domain uses a higher-risk top-level domain.", 8)
    if parsed.port and parsed.port not in (80, 443):
        score = _add(reasons, score, "The link uses an unusual network port.", 10)
    if any(path.endswith(extension) for extension in RISKY_EXTENSIONS):
        score = _add(reasons, score, "The link appears to download a potentially dangerous file.", 35)

    compact_host = host.replace("-", "").replace(".", "")
    for brand in BRANDS:
        # A brand within a non-official, padded domain is a common impersonation pattern.
        if brand in compact_host and not host.endswith(f"{brand}.com") and host != f"{brand}.com":
            score = _add(reasons, score, f"The domain may be impersonating {brand.title()}.", 25)
            break
    return score


def _analyse_email_headers(text: str, reasons: list[str], score: int) -> int:
    if not re.search(r"(?im)^(from|return-path|reply-to|subject):", text):
        return score
    message = Parser(policy=policy.default).parsestr(text, headersonly=True)
    def address_domain(header: str) -> str:
        address = parseaddr(header)[1]
        return _extract_domain(address.rsplit("@", 1)[1]) if "@" in address else ""

    from_domain = address_domain(message.get("From", ""))
    reply_domain = address_domain(message.get("Reply-To", ""))
    return_domain = address_domain(message.get("Return-Path", ""))
    if from_domain and reply_domain and from_domain != reply_domain:
        score = _add(reasons, score, "The Reply-To address differs from the visible sender.", 20)
    if from_domain and return_domain and from_domain != return_domain:
        score = _add(reasons, score, "The return-path domain differs from the visible sender.", 15)
    auth = message.get("Authentication-Results", "").lower()
    if "dmarc=fail" in auth or "spf=fail" in auth or "dkim=fail" in auth:
        score = _add(reasons, score, "Email authentication checks reported a failure.", 35)
    return score


def analyze_submission(text: str) -> dict:
    """Return a transparent risk assessment for untrusted user-provided text."""
    text = (text or "").strip()
    lowered = text.lower()
    reasons: list[str] = []
    score = 0
    urls = [item.rstrip(".,;:!?)]}\"") for item in URL_PATTERN.findall(text)]

    for url in urls:
        score = _analyse_url(url, reasons, score)
    score = _analyse_email_headers(text, reasons, score)

    if any(term in lowered for term in URGENCY_TERMS):
        score = _add(reasons, score, "The message uses urgency or an account-threat tactic.", 12)
    if any(term in lowered for term in CREDENTIAL_TERMS):
        score = _add(reasons, score, "The message asks for login or verification information.", 18)
    if any(term in lowered for term in PAYMENT_TERMS):
        score = _add(reasons, score, "The message requests an unusual or hard-to-reverse payment.", 15)
    if urls and any(term in lowered for term in CREDENTIAL_TERMS + URGENCY_TERMS):
        score = _add(reasons, score, "A link is combined with a common phishing request.", 15)

    score = min(score, 100)
    if score >= 70:
        verdict = "malicious"
        action = "Do not open the link, download files, reply, or share credentials. Delete or report the message."
    elif score >= 40:
        verdict = "scam"
        action = "Treat this as a likely scam. Verify independently using an official website or known phone number."
    elif score >= 15:
        verdict = "suspicious"
        action = "Do not act yet. Check the sender and destination independently before proceeding."
    else:
        verdict = "safe"
        action = "No clear warning signs were found. This is not a guarantee that the content is safe."

    return {
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons or ["No high-confidence phishing or malicious indicators were detected."],
        "recommended_action": action,
        "urls": urls,
        "disclaimer": "This is a local heuristic assessment. Submitted links were not opened or executed.",
    }


def format_security_alert(assessment: dict) -> str:
    """Format a compact in-chat warning without exposing untrusted markup."""
    reasons = "\n".join(f"• {reason}" for reason in assessment["reasons"][:4])
    return (
        f"Security assessment: {assessment['verdict'].upper()} "
        f"({assessment['risk_score']}/100)\n{reasons}\n\n"
        f"Recommended action: {assessment['recommended_action']}\n"
        "Note: the link was not opened or executed."
    )
