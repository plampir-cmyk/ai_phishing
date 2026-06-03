from __future__ import annotations

import csv
import email
import os
import re
import unicodedata
from dataclasses import dataclass
from email import policy
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from docx import Document

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com", "aol.com", "proton.me", "protonmail.com"
}

URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\basap\b", r"\baction required\b", r"\bfinal warning\b",
    r"\bwithin \d+ hours?\b", r"\bnow\b", r"\btoday\b"
]
SENSITIVE_PATTERNS = [
    r"\bpassword\b", r"\bcredentials\b", r"\bcredit card\b", r"\bbank(ing)? information\b", r"\bssn\b",
    r"\blogin details\b", r"\bverification code\b", r"\baccount number\b"
]
ACTION_PATTERNS = [
    r"\bclick here\b", r"\bverify\b", r"\bconfirm\b", r"\breset\b", r"\blog in\b", r"\bsign in\b",
    r"\bupdate\b", r"\bunlock\b", r"\benroll\b"
]
THREAT_PATTERNS = [
    r"\bsuspended\b", r"\blocked\b", r"\bdeactivated\b", r"\bterminated\b", r"\blocked\b",
    r"\bdisabled\b", r"\block(ed|out)\b", r"\bunauthorized\b", r"\bcompromised\b"
]
GENERIC_GREETING_PATTERNS = [
    r"\bdear customer\b", r"\bdear user\b", r"\bdear valued customer\b", r"\bhello\b", r"\battention\b"
]
EMOTIONAL_PATTERNS = [
    r"\bprotect your information\b", r"\bfor your safety\b", r"\bsecurity alert\b", r"\brisk\b",
    r"\bthreat\b", r"\bfraud\b", r"\bunauthorized\b"
]

CREDENTIAL_LURE_PATTERNS = [
    r"\bsecure link\b", r"\bshared file\b", r"\bvalidation page\b", r"\bre-enter\b", 
    r"\bidentity check\b", r"\bsign in\b", r"\bfile sharing\b", r"\blogin\b",
    r"\bsharepoint\b", r"\bonedrive\b", r"\bdropbox\b", r"\bgoogle drive\b",
    r"\bdocument shared\b", r"\bview document\b", r"\bsecure document\b", r"\bauthenticate\b"
]

URL_REGEX = re.compile(r"https?://[^\s'\">)]+|www\.[^\s'\">)]+", re.I)
IP_URL_REGEX = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|\b)", re.I)
SUSPICIOUS_DOMAIN_REGEX = re.compile(r"(?:paypa1|micr0soft|secure-|verify-|account-|billing-|auth-update|transaction-review)", re.I)

#added for feature use later
TOP_TARGET_BRANDS = {
    "paypal", "microsoft", "apple", "google", "amazon", 
    "netflix", "facebook"
}
LEET_MAP = str.maketrans("@013457!$", "aoieastis")

BENIGN_DICTIONARY_WORDS = {"maple", "ample", "sample", "mac"}

#added for distance calculation for brand spoofing
def _levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2): return _levenshtein_distance(s2, s1)
    if len(s2) == 0: return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]
#end

@dataclass
class ParsedEmail:
    subject: str = ""
    from_addr: str = ""
    to_addr: str = ""
    reply_to: str = ""
    return_path: str = ""


def sanitize_text(text: str) -> str:
    return unicodedata.normalize("NFKD", text).encode("utf-8", "ignore").decode("utf-8", "ignore")


def _read_html(path: str) -> tuple[str, list[str]]:
    with open(path, encoding="utf-8", errors="ignore") as f:
        raw = f.read()
    soup = BeautifulSoup(raw, "html.parser")
    text = soup.get_text(" ", strip=True)
    urls = []
    for a in soup.find_all("a", href=True):
        urls.append(a["href"].strip())
    urls.extend(URL_REGEX.findall(raw))
    return text, sorted(set(urls))


def _read_docx(path: str) -> tuple[str, list[str]]:
    text = "\n".join(p.text for p in Document(path).paragraphs)
    return text, URL_REGEX.findall(text)


def _read_eml(path: str) -> tuple[str, list[str], ParsedEmail]:
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    body_parts = []
    urls = []
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == "text/plain":
            try:
                body_parts.append(part.get_content())
            except Exception:
                pass
        elif content_type == "text/html":
            try:
                html = part.get_content()
                txt, found = _read_html_from_string(html)
                body_parts.append(txt)
                urls.extend(found)
            except Exception:
                pass

    if not body_parts:
        try:
            payload = msg.get_body(preferencelist=("plain", "html"))
            if payload:
                content = payload.get_content()
                if payload.get_content_type() == "text/html":
                    txt, found = _read_html_from_string(content)
                    body_parts.append(txt)
                    urls.extend(found)
                else:
                    body_parts.append(content)
        except Exception:
            pass

    parsed = ParsedEmail(
        subject=str(msg.get("Subject", "") or ""),
        from_addr=str(msg.get("From", "") or ""),
        to_addr=str(msg.get("To", "") or ""),
        reply_to=str(msg.get("Reply-To", "") or ""),
        return_path=str(msg.get("Return-Path", "") or ""),
    )
    full_text = "\n".join(filter(None, [parsed.subject, *body_parts]))
    urls.extend(URL_REGEX.findall(full_text))
    return full_text, sorted(set(urls)), parsed


def _read_html_from_string(raw: str) -> tuple[str, list[str]]:
    soup = BeautifulSoup(raw, "html.parser")
    text = soup.get_text(" ", strip=True)
    urls = [a["href"].strip() for a in soup.find_all("a", href=True)]
    urls.extend(URL_REGEX.findall(raw))
    return text, sorted(set(urls))


def extract_content(path: str) -> dict[str, Any]:
    ext = Path(path).suffix.lower()
    if ext == ".html":
        text, urls = _read_html(path)
        headers = ParsedEmail()
    elif ext == ".docx":
        text, urls = _read_docx(path)
        headers = ParsedEmail()
    elif ext == ".eml":
        text, urls, headers = _read_eml(path)
    else:
        raise ValueError(f"Unsupported file type: {ext}")

    text = sanitize_text(text)
    return {"text": text, "urls": urls, "headers": headers}


def _count_matches(text: str, patterns: list[str]) -> int:
    return sum(1 for p in patterns if re.search(p, text, re.I))


def get_header_anomalies(headers: ParsedEmail) -> list[str]:
    anomalies: list[str] = []
    from_domain = extract_domain(headers.from_addr)
    reply_domain = extract_domain(headers.reply_to)
    return_domain = extract_domain(headers.return_path)

    if from_domain and from_domain in FREE_EMAIL_DOMAINS:
        anomalies.append("From address uses a free email provider")
    if from_domain and reply_domain and from_domain != reply_domain:
        anomalies.append("Reply-To domain differs from From domain")
    if from_domain and return_domain and from_domain != return_domain:
        anomalies.append("Return-Path domain differs from From domain")
    return anomalies


def extract_domain(value: str) -> str:
    if not value:
        return ""
    match = re.search(r"@([A-Za-z0-9.-]+)", value)
    return match.group(1).lower() if match else ""


def compute_handcrafted_features(text: str, urls: list[str] | None = None, headers: ParsedEmail | None = None) -> dict[str, float]:
    urls = urls or []
    headers = headers or ParsedEmail()
    lowered = text.lower()
    words = re.findall(r"\b\w+\b", lowered)
    
    
    word_count = max(len(words), 1) 
    exclamations = text.count("!")
    uppercase_ratio = (sum(1 for c in text if c.isupper()) / max(len(text), 1))

    suspicious_domains = 0
    ip_urls = 0
    shorteners = 0
    
    #new feature values
    max_subdomain_depth = 0
    max_domain_hyphens = 0
    brand_spoofing_hits = 0

    for url in urls:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        host = (parsed.netloc or parsed.path).lower()
        
        if IP_URL_REGEX.search(url):
            ip_urls += 1
        if SUSPICIOUS_DOMAIN_REGEX.search(host):
            suspicious_domains += 1
        if any(short in host for short in ["bit.ly", "tinyurl.com", "t.co", "rb.gy"]):
            shorteners += 1

        #improved domain analysis feature 
        domain_parts = host.split('.')
        max_subdomain_depth = max(max_subdomain_depth, len(domain_parts))
        max_domain_hyphens = max(max_domain_hyphens, host.count('-'))

        #brand spoofing feature
        for part in domain_parts:
            if len(part) < 4:
                continue 
            
            normalized_part = part.translate(LEET_MAP)
            if normalized_part in BENIGN_DICTIONARY_WORDS:
                continue

            for brand in TOP_TARGET_BRANDS:
                
                if normalized_part == brand:
                    continue 
                
                if brand in normalized_part:
                    brand_spoofing_hits += 1
                    break
                
                dist = _levenshtein_distance(normalized_part, brand)
                max_allowed_typos = 2 if len(brand) > 6 else 1
                
                if 0 < dist <= max_allowed_typos:
                    brand_spoofing_hits += 1
                    break

    header_anomalies = len(get_header_anomalies(headers))
    
    #urgent words ratio feature
    action_count = _count_matches(lowered, ACTION_PATTERNS)
    action_density = action_count / word_count
    
    #fake threads feature
    subject_lower = headers.subject.lower()
    fake_thread_count = subject_lower.count("re:") + subject_lower.count("fwd:") + subject_lower.count("fw:")

    #subtle credential request feature
    credential_lure_count = float(_count_matches(lowered, CREDENTIAL_LURE_PATTERNS))

    return {
        
        "char_count": float(len(text)),
        "word_count": float(len(words)),
        "url_count": float(len(urls)),
        "ip_url_count": float(ip_urls),
        "suspicious_domain_count": float(suspicious_domains),
        "url_shortener_count": float(shorteners),
        "urgency_count": float(_count_matches(lowered, URGENCY_PATTERNS)),
        "sensitive_count": float(_count_matches(lowered, SENSITIVE_PATTERNS)),
        "action_count": float(action_count), 
        "threat_count": float(_count_matches(lowered, THREAT_PATTERNS)),
        "generic_greeting_count": float(_count_matches(lowered, GENERIC_GREETING_PATTERNS)),
        "emotional_tone_count": float(_count_matches(lowered, EMOTIONAL_PATTERNS)),
        "exclamation_count": float(exclamations),
        "uppercase_ratio": float(round(uppercase_ratio, 5)),
        "header_anomaly_count": float(header_anomalies),
        
        #added feature's return 
        "max_subdomain_depth": float(max_subdomain_depth),
        "max_domain_hyphens": float(max_domain_hyphens),
        "brand_spoofing_hits": float(brand_spoofing_hits),
        "action_density": float(round(action_density, 5)),
        "fake_thread_count": float(fake_thread_count),
        "credential_lure_count": float(credential_lure_count),
    }


def phishing_cues(text: str, urls: list[str] | None = None, headers: ParsedEmail | None = None) -> list[str]:
    urls = urls or []
    headers = headers or ParsedEmail()
    cues: list[str] = []
    
    #changed the cue.append('text') to improve explanation messages returned to the user
    if _count_matches(text, URGENCY_PATTERNS):
        cues.append("High-pressure urgency language detected (e.g., 'Action required', 'ASAP')")
    if _count_matches(text, ACTION_PATTERNS):
        cues.append("Suspicious call-to-action detected (e.g., 'Click here', 'Verify')")
    if _count_matches(text, SENSITIVE_PATTERNS):
        cues.append("Requests sensitive data like passwords or credit cards")
    if _count_matches(text, THREAT_PATTERNS):
        cues.append("Threatening language detected (e.g., 'Account suspended')")
    if _count_matches(text, GENERIC_GREETING_PATTERNS):
        cues.append("Uses a generic greeting instead of your actual name")
    if _count_matches(text, EMOTIONAL_PATTERNS):
        cues.append("Uses fear or emotional manipulation (e.g., 'Security alert')")
    if any(IP_URL_REGEX.search(u) for u in urls):
        cues.append("Contains an IP address link instead of a proper domain (major red flag)")
    if any(SUSPICIOUS_DOMAIN_REGEX.search(u) for u in urls):
        cues.append("Contains a link to a known spoofed or suspicious domain")

    #added dictioneries inside phishing_cues() 
    finance_patterns = [r"\binvoice\b", r"\bpayment\b", r"\bcrypto(currency)?\b", r"\bbitcoin\b", r"\bwire transfer\b", r"\breimbursement\b"]
    if _count_matches(text, finance_patterns):
        cues.append("Contains financial lures like invoices, payments, or cryptocurrency")

    impersonation_patterns = [r"\bit department\b", r"\bhuman resources\b", r"\bmanagement\b", r"\bsystem administrator\b", r"\bhelp desk\b", r"\bsecurity team\b", r"\bsecurity desk\b", r"\bit security\b"]
    if _count_matches(text, impersonation_patterns):
        cues.append("Attempts to impersonate authority figures (e.g., IT, HR, or Management)")

    cloud_patterns = [r"\bshared a document\b", r"\bsecure document\b", r"\bdocuSign\b", r"\bsharepoint\b", r"\bonedrive\b", r"\bshared report\b", r"\bdocument service\b"]
    if _count_matches(text, cloud_patterns):
        cues.append("Disguised as a cloud document share or e-signature request")

    suspension_patterns = [r"\baccount has been suspended\b", r"\bsuspicious activity\b", r"\bunusual activity\b", r"\bmailbox will be locked\b", r"\baccess will be suspended\b"]
    if _count_matches(text, suspension_patterns):
        cues.append("Warns about account suspension or unusual activity (common phishing scare tactic)")

    cues.extend(get_header_anomalies(headers))
    return cues


#corrected from the given code 
def build_numeric_feature_frame(series):
    rows = []
    for text in series:
        text_str = str(text)
        found_urls = URL_REGEX.findall(text_str)
        rows.append(compute_handcrafted_features(text_str, urls=found_urls, headers=None))
    return __import__("pandas").DataFrame(rows)

def log_result(log_path: str, row: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    file_exists = os.path.exists(log_path)
    with open(log_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp", "filename", "prediction", "risk_score", "model_probability",
                "cue_count", "header_anomaly_count", "triggered_cues"
            ],
        )
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)
