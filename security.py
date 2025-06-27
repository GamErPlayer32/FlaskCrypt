import re
import html
from flask import jsonify

def check(msg, rules=["html", "sql", "security"]):
    msg = msg.strip()

    if "html" in rules:
        msg = rule_html(msg)
        if msg.startswith("Error:"):
            return msg

    if "sql" in rules:
        msg = rule_sql(msg)
        if msg.startswith("Error:"):
            return msg

    if "security" in rules:
        msg = rule_security(msg)
        if msg.startswith("Error:"):
            return msg

    # Optional: Escape anything dangerous
    return html.escape(msg)

def deep_sanitize(obj, rules=["html", "sql", "security"], exclude_keys=None):
    if exclude_keys is None:
        exclude_keys = set()

    if isinstance(obj, dict):
        return {
            key: deep_sanitize(value, rules, exclude_keys)
            if key not in exclude_keys else value
            for key, value in obj.items()
        }
    elif isinstance(obj, list):
        return [deep_sanitize(item, rules, exclude_keys) for item in obj]
    elif isinstance(obj, str):
        return check(obj, rules)
    return obj

def validate_aes_params(key: bytes, iv: list, sbox: list, aes_size: int):
    """Validate AES key, IV, and SBOX format and lengths."""
    expected_key_length = aes_size // 8

    if not isinstance(key, (bytes, bytearray)) or len(key) != expected_key_length:
        return jsonify({'error': f'Invalid AES key: expected {expected_key_length} bytes'}), 400

    if not isinstance(iv, list) or len(iv) != 16:
        return jsonify({'error': f'Invalid IV: expected 16 bytes, got {len(iv)}'}), 400

    if not isinstance(sbox, list) or len(sbox) != 256:
        return jsonify({'error': f'Invalid SBOX: expected 256 entries, got {len(sbox)}'}), 400

    return None  # No error


def rule_html(msg):
    # Check for any HTML tags using regex
    if re.search(r'<[^>]+>', msg):
        return "Error: HTML tags are not allowed."
    return msg


def rule_sql(msg):
    # Check for common SQL injection keywords or patterns
    patterns = [
        r"\bSELECT\b", r"\bINSERT\b", r"\bUPDATE\b", r"\bDELETE\b",
        r"\bDROP\b", r"\bUNION\b", r"--", r";", r"' OR '1'='1",
        r"xp_cmdshell", r"exec\s*\(", r"information_schema", r"benchmark\s*\(",
        r"\bCREATE\b", r"\bALTER\b", r"\bTRUNCATE\b", r"\bREPLACE\b"
    ]
    for pattern in patterns:
        if re.search(pattern, msg, re.IGNORECASE):
            return "Error: SQL injection detected."
    return msg


def rule_security(msg):
    # Check for JavaScript/XSS/browser attacks
    patterns = [
        r"\bscript\b", r"\balert\s*\(", r"\beval\s*\(",
        r"\bexec\s*\(", r"base64_(en|de)code\s*\(",
        r"\bdocument\.cookie\b", r"\bwindow\.location\b",
        r"\bXMLHttpRequest\b", r"\bfetch\s*\(",
        r"\bwindow\.open\s*\(", r"\bwindow\.close\s*\(",
        r"\blocalStorage\b", r"\bsessionStorage\b",
        r"\bconsole\.log\s*\(", r"\bconsole\.error\s*\(",
        r"\bdocument\.write\s*\(", r"\bdocument\.writeln\s*\(",
        r"\bwindow\.alert\s*\(", r"\bwindow\.confirm\s*\(",
        r"\bwindow\.prompt\s*\(", r"\bwindow\.print\s*\(",
        r"\bwindow\.location\.href\b", r"\bwindow\.location\.replace\s*\(",
        r"\bwindow\.history\b", r"\bwindow\.history\.back\s*\("
    ]
    for pattern in patterns:
        if re.search(pattern, msg, re.IGNORECASE):
            return "Error: Security threat detected."
    return msg
