#!/usr/bin/env python3
"""
MailGuard In-Sandbox Static Inspector Agent
Pure Python Standard Library - ZERO external dependencies.
Executed inside isolated Celesto MicroVM (Network: OFF).
Outputs validated JSON to stdout.
"""

import sys
import os
import re
import json
import math
import time
import email
import hashlib
from email import policy
from urllib.parse import urlparse

# Suspicious extensions (scripts, executables, installers)
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", 
    ".cpl", ".jar", ".msi", ".dll", ".so", ".sh", ".com", ".pif"
}

ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".7z", ".rar", ".bz2"}

# Common targeted brand strings for homoglyph / typosquatting detection
POPULAR_BRANDS = [
    "google", "microsoft", "apple", "amazon", "paypal", "netflix",
    "facebook", "instagram", "linkedin", "github", "dropbox", "wellsfargo"
]

# Prompt injection signature patterns
PROMPT_INJECTION_PATTERNS = [
    (r"(?i)\bignore\s+(all\s+)?(previous|prior)\s+(instructions|directives|prompts)\b", "INSTRUCTION_RESET", 0.95),
    (r"(?i)\bsystem\s+override\b", "SYSTEM_OVERRIDE", 0.95),
    (r"(?i)\bdisregard\s+(all\s+)?(previous|prior|above)\b", "INSTRUCTION_RESET", 0.90),
    (r"(?i)\byou\s+are\s+now\s+(in\s+)?(developer\s+mode|unrestricted|DAN)\b", "JAILBREAK_ATTEMPT", 0.95),
    (r"(?i)\[\s*(system|admin|override)\s*\]", "FAKED_SYSTEM_ROLE", 0.90),
    (r"(?i)\b(print|reveal|expose|output|send)\s+(my\s+|the\s+|all\s+)?(api\s*keys?|secrets?|tokens?|password)\b", "CREDENTIAL_EXFILTRATION", 0.95),
    (r"(?i)\b(delete|trash|archive)\s+(all\s+)?(emails?|messages?|inbox)\b", "MALICIOUS_TOOL_MANIPULATION", 0.85),
    (r"(?i)\b(forward|send|relay)\s+all\s+(emails?|data|messages?)\s+to\b", "EXFILTRATION_TRIGGER", 0.90),
    (r"(?i)\bconfirm\s+payment\s+of\s+\$[0-9,]+(\.[0-9]{2})?\s+to\b", "UNAUTHORIZED_FINANCIAL_ACTION", 0.85),
]

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)

def strip_html_tags(html_str: str) -> str:
    """Remove HTML tags cleanly using standard library regex."""
    clean = re.sub(r"<style.*?</style>", " ", html_str, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"<script.*?</script>", " ", clean, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean

# Leetspeak translation table to detect obfuscated brand impersonation
LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"
})

def check_homoglyph_or_typo(domain: str) -> tuple[bool, str]:
    """Check for brand typosquatting, leetspeak, or punycode."""
    d_clean = domain.lower()
    
    # 1. Detect punycode
    if "xn--" in d_clean:
        return True, f"Internationalized / Punycode domain detected: '{domain}'"

    # 2. Detect leetspeak brand substitution
    d_normalized = d_clean.translate(LEET_MAP)
    for brand in POPULAR_BRANDS:
        if brand in d_normalized and brand not in d_clean:
            return True, f"Possible typosquatting/leetspeak impersonation of '{brand}' (detected '{domain}')"
        if f"-{brand}" in d_clean or f"{brand}-" in d_clean:
            return True, f"Suspicious brand hyphenation detected for '{brand}'"

    return False, ""

def extract_urls_from_text(text: str) -> list:
    """Extract URLs and perform static safety heuristics."""
    found_urls = re.findall(r"https?://[^\s<>\"']+", text)
    results = []
    seen = set()

    for u in found_urls:
        if u in seen:
            continue
        seen.add(u)
        try:
            parsed = urlparse(u)
            host = parsed.hostname or ""
            is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))
            is_homo, notes = check_homoglyph_or_typo(host)
            
            # Suspicious TLD check
            suspicious_tld = any(host.endswith(tld) for tld in [".top", ".xyz", ".fit", ".tk", ".ml", ".ga", ".cf", ".click"])
            
            risk_notes = []
            if is_ip:
                risk_notes.append("Raw IPv4 address used in URL")
            if is_homo:
                risk_notes.append(notes)
            if suspicious_tld:
                risk_notes.append("Suspicious / high-abuse top-level domain")

            results.append({
                "url": u,
                "domain": host,
                "is_ip_address": is_ip,
                "is_suspicious_homoglyph": is_homo,
                "is_known_suspicious_tld": suspicious_tld,
                "risk_notes": "; ".join(risk_notes) if risk_notes else None
            })
        except Exception:
            results.append({
                "url": u,
                "domain": "unknown",
                "is_ip_address": False,
                "is_suspicious_homoglyph": False,
                "is_known_suspicious_tld": False,
                "risk_notes": "Malformed URL"
            })
    return results

def detect_prompt_injections(text: str) -> list:
    """Scan text for known prompt injection patterns and evasion signatures."""
    signals = []

    # 1. Regex pattern matches
    for pattern, p_type, conf in PROMPT_INJECTION_PATTERNS:
        match = re.search(pattern, text)
        if match:
            signals.append({
                "pattern_type": p_type,
                "confidence": conf,
                "matched_snippet": match.group(0)[:120],
                "description": f"Detected prompt injection pattern: {p_type}"
            })

    # 2. Hidden Unicode Detection
    zero_width_chars = ["\u200b", "\u200c", "\u200d", "\ufeff"]
    for zwc in zero_width_chars:
        if zwc in text:
            count = text.count(zwc)
            signals.append({
                "pattern_type": "HIDDEN_UNICODE",
                "confidence": 0.88,
                "matched_snippet": f"{count} zero-width unicode characters found",
                "description": "Invisible zero-width characters detected (often used for prompt injection evasion)"
            })
            break

    # 3. Base64 payload detection in plain text
    b64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", text)
    for b64_cand in b64_matches:
        if len(b64_cand) > 32:
            signals.append({
                "pattern_type": "EMBEDDED_BASE64",
                "confidence": 0.75,
                "matched_snippet": b64_cand[:60] + "...",
                "description": "Embedded base64 payload detected in email text"
            })
            break

    return signals

def inspect_eml(eml_bytes: bytes) -> dict:
    start_time = time.time()
    threat_indicators = []

    # Parse message with default email policy
    try:
        msg = email.message_from_bytes(eml_bytes, policy=policy.default)
    except Exception as e:
        msg = email.message_from_bytes(eml_bytes)

    subject = str(msg.get("subject", "") or "")
    sender = str(msg.get("from", "") or "")
    recipient = str(msg.get("to", "") or "")
    date_str = str(msg.get("date", "") or "")

    body_plain_parts = []
    body_html_parts = []
    attachments_meta = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", "") or "")
            filename = part.get_filename()

            if filename or "attachment" in disposition.lower():
                # Process attachment metadata (ZERO EXECUTION)
                payload_bytes = part.get_payload(decode=True) or b""
                fn = filename or "unnamed_attachment"
                ext = os.path.splitext(fn)[1].lower()
                size = len(payload_bytes)
                sha = hashlib.sha256(payload_bytes).hexdigest()
                entropy = calculate_shannon_entropy(payload_bytes)

                is_dangerous_ext = ext in DANGEROUS_EXTENSIONS
                is_archive = ext in ARCHIVE_EXTENSIONS
                traversal_risk = False
                suspicious_notes = []

                if is_dangerous_ext:
                    suspicious_notes.append(f"Executable or dangerous script extension '{ext}'")
                    threat_indicators.append({
                        "indicator_type": "DANGEROUS_ATTACHMENT",
                        "severity": "CRITICAL",
                        "description": f"Attachment '{fn}' has dangerous extension '{ext}'",
                        "matched_pattern": ext
                    })

                if entropy > 7.5:
                    suspicious_notes.append("High Shannon entropy (>7.5) indicating packed/encrypted content")
                    threat_indicators.append({
                        "indicator_type": "HIGH_ENTROPY_ATTACHMENT",
                        "severity": "HIGH",
                        "description": f"Attachment '{fn}' has high entropy {entropy}",
                        "matched_pattern": f"entropy={entropy}"
                    })

                # Safe Zip structure inspection without extraction
                if is_archive and ext == ".zip":
                    try:
                        import zipfile
                        import io
                        with zipfile.ZipFile(io.BytesIO(payload_bytes)) as zf:
                            for zip_entry in zf.namelist():
                                if ".." in zip_entry or zip_entry.startswith("/") or zip_entry.startswith("\\"):
                                    traversal_risk = True
                                    suspicious_notes.append(f"Zip-slip path traversal entry: '{zip_entry}'")
                                    threat_indicators.append({
                                        "indicator_type": "ZIP_SLIP_ATTEMPT",
                                        "severity": "CRITICAL",
                                        "description": f"Zip entry '{zip_entry}' contains directory traversal attempt",
                                        "matched_pattern": zip_entry
                                    })
                                    break
                    except Exception:
                        pass

                attachments_meta.append({
                    "filename": fn,
                    "content_type": content_type,
                    "size_bytes": size,
                    "sha256_hash": sha,
                    "entropy": entropy,
                    "is_executable_or_script": is_dangerous_ext,
                    "is_archive": is_archive,
                    "archive_traversal_risk": traversal_risk,
                    "suspicious_notes": "; ".join(suspicious_notes) if suspicious_notes else None
                })
            else:
                if content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_plain_parts.append(payload.decode("utf-8", errors="replace"))
                    except Exception:
                        pass
                elif content_type == "text/html":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_html_parts.append(payload.decode("utf-8", errors="replace"))
                    except Exception:
                        pass
    else:
        # Non-multipart message
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True) or b""
        decoded_text = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else str(payload)
        if content_type == "text/html":
            body_html_parts.append(decoded_text)
        else:
            body_plain_parts.append(decoded_text)

    # Combine text
    has_html = len(body_html_parts) > 0
    full_plain = "\n".join(body_plain_parts)
    if not full_plain.strip() and body_html_parts:
        full_plain = strip_html_tags("\n".join(body_html_parts))

    sanitized_text = full_plain.strip()

    # URL Extraction & Checks
    extracted_urls = extract_urls_from_text(sanitized_text + " " + " ".join(body_html_parts))
    for url_info in extracted_urls:
        if url_info["is_ip_address"]:
            threat_indicators.append({
                "indicator_type": "PHISHING_IP_URL",
                "severity": "HIGH",
                "description": f"Direct IP address URL found: {url_info['url']}",
                "matched_pattern": url_info["domain"]
            })
        if url_info["is_suspicious_homoglyph"]:
            threat_indicators.append({
                "indicator_type": "TYPOSQUATTING_HOMOGLYPH",
                "severity": "CRITICAL",
                "description": f"Typosquatting/Homoglyph link: {url_info['risk_notes']}",
                "matched_pattern": url_info["domain"]
            })

    # Prompt Injection Detection
    prompt_signals = detect_prompt_injections(sanitized_text + " " + subject)
    for sig in prompt_signals:
        threat_indicators.append({
            "indicator_type": "PROMPT_INJECTION",
            "severity": "CRITICAL" if sig["confidence"] >= 0.9 else "HIGH",
            "description": sig["description"],
            "matched_pattern": sig["matched_snippet"]
        })

    # Risk Scoring
    risk_score = 0.0
    for ti in threat_indicators:
        sev = ti["severity"]
        if sev == "CRITICAL":
            risk_score += 0.45
        elif sev == "HIGH":
            risk_score += 0.25
        elif sev == "MEDIUM":
            risk_score += 0.15
        else:
            risk_score += 0.05

    risk_score = min(1.0, round(risk_score, 2))

    if risk_score >= 0.70:
        risk_label = "CRITICAL"
    elif risk_score >= 0.45:
        risk_label = "SUSPICIOUS"
    elif risk_score >= 0.25:
        risk_label = "MEDIUM"
    elif risk_score > 0.05:
        risk_label = "LOW"
    else:
        risk_label = "SAFE"

    duration_ms = int((time.time() - start_time) * 1000)

    return {
        "status": "success",
        "subject": subject,
        "sender": sender,
        "recipient": recipient,
        "date_str": date_str,
        "has_html": has_html,
        "sanitized_text": sanitized_text,
        "extracted_urls": extracted_urls,
        "attachments": attachments_meta,
        "threat_indicators": threat_indicators,
        "prompt_injection_signals": prompt_signals,
        "static_risk_score": risk_score,
        "static_risk_label": risk_label,
        "analysis_duration_ms": duration_ms
    }

def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: inspector.py <path_to_raw_eml>\n")
        sys.exit(1)

    eml_path = sys.argv[1]
    if not os.path.exists(eml_path):
        sys.stderr.write(f"File not found: {eml_path}\n")
        sys.exit(1)

    try:
        with open(eml_path, "rb") as f:
            raw_bytes = f.read()
    except Exception as e:
        sys.stderr.write(f"Failed to read file: {e}\n")
        sys.exit(1)

    try:
        result = inspect_eml(raw_bytes)
        json_output = json.dumps(result, indent=2)
        # Print strictly valid JSON to stdout
        sys.stdout.write(json_output + "\n")
        sys.stdout.flush()
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"Inspection error: {e}\n")
        sys.exit(2)

if __name__ == "__main__":
    main()
