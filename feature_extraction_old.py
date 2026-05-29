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
URL_REGEX = re.compile(r"https?://[^\s'\">)]+|www\.[^\s'\">)]+", re.I)
IP_URL_REGEX = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|\b)", re.I)
SUSPICIOUS_DOMAIN_REGEX = re.compile(r"(?:paypa1|micr0soft|secure-|verify-|account-|billing-|auth-update|transaction-review)", re.I)


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
    exclamations = text.count("!")
    uppercase_ratio = (sum(1 for c in text if c.isupper()) / max(len(text), 1))

    suspicious_domains = 0
    ip_urls = 0
    shorteners = 0
    for url in urls:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        host = (parsed.netloc or parsed.path).lower()
        if IP_URL_REGEX.search(url):
            ip_urls += 1
        if SUSPICIOUS_DOMAIN_REGEX.search(host):
            suspicious_domains += 1
        if any(short in host for short in ["bit.ly", "tinyurl.com", "t.co", "rb.gy"]):
            shorteners += 1

    header_anomalies = len(get_header_anomalies(headers))
    return {
        "char_count": float(len(text)),
        "word_count": float(len(words)),
        "url_count": float(len(urls)),
        "ip_url_count": float(ip_urls),
        "suspicious_domain_count": float(suspicious_domains),
        "url_shortener_count": float(shorteners),
        "urgency_count": float(_count_matches(lowered, URGENCY_PATTERNS)),
        "sensitive_count": float(_count_matches(lowered, SENSITIVE_PATTERNS)),
        "action_count": float(_count_matches(lowered, ACTION_PATTERNS)),
        "threat_count": float(_count_matches(lowered, THREAT_PATTERNS)),
        "generic_greeting_count": float(_count_matches(lowered, GENERIC_GREETING_PATTERNS)),
        "emotional_tone_count": float(_count_matches(lowered, EMOTIONAL_PATTERNS)),
        "exclamation_count": float(exclamations),
        "uppercase_ratio": float(round(uppercase_ratio, 5)),
        "header_anomaly_count": float(header_anomalies),
    }


def phishing_cues(text: str, urls: list[str] | None = None, headers: ParsedEmail | None = None) -> list[str]:
    urls = urls or []
    headers = headers or ParsedEmail()
    cues: list[str] = []
    if _count_matches(text, URGENCY_PATTERNS):
        cues.append("Urgency language detected")
    if _count_matches(text, ACTION_PATTERNS):
        cues.append("Action-oriented request detected")
    if _count_matches(text, SENSITIVE_PATTERNS):
        cues.append("Sensitive information request detected")
    if _count_matches(text, THREAT_PATTERNS):
        cues.append("Threat or punishment language detected")
    if _count_matches(text, GENERIC_GREETING_PATTERNS):
        cues.append("Generic greeting detected")
    if _count_matches(text, EMOTIONAL_PATTERNS):
        cues.append("Fear or emotional manipulation language detected")
    if any(IP_URL_REGEX.search(u) for u in urls):
        cues.append("IP-based URL detected")
    if any(SUSPICIOUS_DOMAIN_REGEX.search(u) for u in urls):
        cues.append("Potential spoofed or suspicious domain detected")
    cues.extend(get_header_anomalies(headers))
    return cues



def build_numeric_feature_frame(series):
    rows = []
    for text in series:
        rows.append(compute_handcrafted_features(str(text), urls=[], headers=None))
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