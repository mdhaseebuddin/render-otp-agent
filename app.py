#!/usr/bin/env python3
"""
Render Real-Time OTP Webhook Receiver & Email Dispatcher for VeloTest
=====================================================================
A high-performance, asynchronous FastAPI application that receives real-time
log streams from Render via HTTPS Webhook / Log Drain, dynamically extracts
the target user's email address and OTP code from VeloTest platform logs, and
dispatches an email immediately via Brevo API or Gmail SMTP SSL.

Seamlessly accommodates VeloTest without requiring any changes to VeloTest itself.
Runs 100% free on Render's Web Service free tier.
"""

import os
import re
import ssl
import gzip
import json
import time
import logging
import urllib.request
import urllib.error
from typing import Optional, Tuple, List, Dict, Any
from datetime import datetime, timezone
import smtplib
from email.message import EmailMessage

from fastapi import FastAPI, Request, BackgroundTasks, HTTPException, Header, status
from fastapi.responses import JSONResponse

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ==========================================
# LOGGING SETUP
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("velotest_otp_webhook")

# ==========================================
# CONFIGURATION
# ==========================================
# Dispatch provider: 'auto', 'brevo', or 'gmail' / 'smtp'
EMAIL_PROVIDER = os.getenv("EMAIL_PROVIDER", "auto").strip().lower()

# Brevo (Sendinblue) REST API Credentials
BREVO_API_KEY = os.getenv("BREVO_API_KEY", "").strip()
BREVO_SENDER_EMAIL = os.getenv("BREVO_SENDER_EMAIL", "").strip() or os.getenv("EMAIL_USER", "").strip()
BREVO_SENDER_NAME = os.getenv("BREVO_SENDER_NAME", "").strip() or os.getenv("APP_NAME", "VeloTest Verification").strip()

# Gmail / SMTP SSL Credentials
EMAIL_USER = os.getenv("EMAIL_USER", "").strip()
EMAIL_PASS = os.getenv("EMAIL_PASS", "").strip()
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))

# Webhook Security & App Settings
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()
APP_NAME = os.getenv("APP_NAME", "VeloTest Verification").strip()
DEDUP_CACHE_TTL = int(os.getenv("DEDUP_CACHE_TTL", "300"))

# In-memory deduplication store: {(email, otp): timestamp}
_recent_dispatches: Dict[Tuple[str, str], float] = {}

# ==========================================
# REGEX PATTERNS FOR EMAIL & OTP
# ==========================================
EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    re.IGNORECASE
)

# Pattern 1: Email then OTP
# Matches:
#   "OTP sent to user@example.com: 593821"
#   "Verification code for student@velotest.com is 123456"
#   "OTP for user@example.com: 123456"
#   "candidate user@example.com OTP: 123456"
PATTERN_EMAIL_THEN_OTP = re.compile(
    r"(?i)\b(?:otp|verification(?:\s*code)?|security\s*code|auth(?:entication)?\s*code|login\s*code|passcode|token|pin|code)\s*(?:sent\s*to|for|to|user|student|candidate)?\s*[:=]?\s*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)[^\d\n\r]{1,35}?([0-9]{4,8})\b"
)

# Pattern 2: OTP then Email
# Matches:
#   "Sent OTP 593821 to user@example.com"
#   "Generated OTP 123456 for candidate user@example.com"
#   "[VeloTest] OTP: 123456 sent to user@example.com"
#   "Code 123456 generated for student@test.org"
PATTERN_OTP_THEN_EMAIL = re.compile(
    r"(?i)\b(?:otp|verification(?:\s*code)?|security\s*code|auth(?:entication)?\s*code|login\s*code|passcode|token|pin|code)\s*(?:is|:|=|-)?\s*([0-9]{4,8})[^\n\r]*?\b(?:to|for|user|student|candidate|email)\s*[:=]?\s*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b"
)

# Pattern 3: Key-Value / Structured format
# Matches:
#   "user: user@example.com | otp: 123456"
#   "email: user@example.com, code: 123456"
#   "student: user@example.com - pin: 1234"
PATTERN_KV_EMAIL_OTP = re.compile(
    r"(?i)\b(?:user|email|student|candidate|recipient|to)\s*[:=]\s*['\"]?([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)['\"]?[^\n\r]*?\b(?:otp|code|verification|passcode|pin|token)\s*[:=]\s*['\"]?([0-9]{4,8})['\"]?\b"
)

# Standalone OTP matcher (4 to 8 digits)
PATTERN_STANDALONE_OTP = re.compile(
    r"(?i)\b(?:otp|verification(?:\s*code)?|security\s*code|auth(?:entication)?\s*code|login\s*code|one[- ]time\s*password|passcode|pin|token|code)\s*(?:is|:|=|-)?\s*['\"]?([0-9]{4,8})['\"]?\b"
)

# Optional user-defined custom regex override
CUSTOM_REGEX = os.getenv("OTP_CUSTOM_REGEX", "").strip()
COMPILED_CUSTOM_REGEX = re.compile(CUSTOM_REGEX, re.IGNORECASE) if CUSTOM_REGEX else None


# ==========================================
# PARSER & DEDUPLICATION LOGIC
# ==========================================
def parse_log_for_email_and_otp(message: str) -> Optional[Tuple[str, str]]:
    """
    Inspect a single log line message and extract both target user email and OTP.
    Accommodates VeloTest platform logs in raw text, structured strings, or embedded JSON.
    Returns (email, otp) tuple if matched, or None.
    """
    if not message or not isinstance(message, str):
        return None

    cleaned_msg = message.strip()

    # 1. Check if the message is or contains an embedded JSON object
    if "{" in cleaned_msg and "}" in cleaned_msg:
        try:
            # Extract JSON substring
            start_idx = cleaned_msg.find("{")
            end_idx = cleaned_msg.rfind("}") + 1
            json_str = cleaned_msg[start_idx:end_idx]
            data = json.loads(json_str)
            if isinstance(data, dict):
                # Look for common email keys
                email_val = None
                for ek in ("email", "user", "student", "candidate", "recipient", "to", "user_email", "student_email"):
                    if ek in data and isinstance(data[ek], str) and "@" in data[ek]:
                        email_val = data[ek].strip()
                        break

                # Look for common OTP keys
                otp_val = None
                for ok in ("otp", "code", "verification_code", "verificationCode", "passcode", "pin", "token", "password"):
                    if ok in data:
                        val_str = str(data[ok]).strip()
                        if val_str.isdigit() and 4 <= len(val_str) <= 8:
                            otp_val = val_str
                            break

                if email_val and otp_val:
                    return email_val, otp_val
        except Exception:
            pass

    # 2. Custom Regex override if specified in environment
    if COMPILED_CUSTOM_REGEX:
        custom_match = COMPILED_CUSTOM_REGEX.search(cleaned_msg)
        if custom_match:
            groups = custom_match.groupdict()
            if "email" in groups and "otp" in groups:
                return groups["email"].strip(), groups["otp"].strip()
            elif len(custom_match.groups()) >= 2:
                g1, g2 = custom_match.group(1).strip(), custom_match.group(2).strip()
                return (g1, g2) if "@" in g1 else (g2, g1)

    # 3. Check Pattern: Email then OTP ("OTP sent to user@example.com: 593821")
    match = PATTERN_EMAIL_THEN_OTP.search(cleaned_msg)
    if match:
        email, otp = match.group(1).strip(), match.group(2).strip()
        return email, otp

    # 4. Check Pattern: OTP then Email ("Sent OTP 593821 to user@example.com")
    match = PATTERN_OTP_THEN_EMAIL.search(cleaned_msg)
    if match:
        otp, email = match.group(1).strip(), match.group(2).strip()
        return email, otp

    # 5. Check Pattern: Structured Key-Value ("user: user@example.com | otp: 123456")
    match = PATTERN_KV_EMAIL_OTP.search(cleaned_msg)
    if match:
        email, otp = match.group(1).strip(), match.group(2).strip()
        return email, otp

    # 6. Universal Heuristic Fallback for VeloTest logs:
    # If the log contains an email and OTP/auth keywords, extract the email and code
    lower_msg = cleaned_msg.lower()
    otp_indicators = (
        "otp", "verification", "verify", "auth", "login",
        "code", "pin", "passcode", "token", "velotest", "exam"
    )
    if any(k in lower_msg for k in otp_indicators):
        email_match = EMAIL_REGEX.search(cleaned_msg)
        if email_match:
            candidate_email = email_match.group(0).strip()
            # Try to match specifically labeled OTP
            otp_match = PATTERN_STANDALONE_OTP.search(cleaned_msg)
            if otp_match:
                return candidate_email, otp_match.group(1).strip()
            # Fall back to any 4 to 8 digit integer not part of the email
            msg_without_email = cleaned_msg.replace(candidate_email, "")
            digits = re.findall(r"\b[0-9]{4,8}\b", msg_without_email)
            if digits:
                # Prefer the last number (standard format: "User requested OTP ... 123456")
                return candidate_email, digits[-1].strip()

    return None


def is_duplicate(email: str, otp: str) -> bool:
    """
    Check if the (email, otp) pair was already dispatched within DEDUP_CACHE_TTL.
    Periodically cleans up expired entries to conserve memory.
    """
    now = time.time()
    key = (email.lower(), otp)

    expired_keys = [k for k, ts in _recent_dispatches.items() if now - ts > DEDUP_CACHE_TTL]
    for k in expired_keys:
        del _recent_dispatches[k]

    if key in _recent_dispatches:
        return True

    _recent_dispatches[key] = now
    return False


# ==========================================
# EMAIL DISPATCH SERVICES (BREVO & GMAIL)
# ==========================================
def dispatch_via_brevo(
    recipient_email: str,
    otp_code: str,
    subject: str,
    text_content: str,
    html_content: str
) -> bool:
    """
    Dispatch transactional email via Brevo REST API (https://api.brevo.com/v3/smtp/email).
    Lightweight, fast, and does not require SMTP port access.
    """
    sender_email = BREVO_SENDER_EMAIL or EMAIL_USER
    if not BREVO_API_KEY or not sender_email:
        logger.error("Brevo dispatch failed: BREVO_API_KEY or sender email is missing!")
        return False

    payload = {
        "sender": {
            "name": BREVO_SENDER_NAME,
            "email": sender_email
        },
        "to": [
            {"email": recipient_email}
        ],
        "subject": subject,
        "htmlContent": html_content,
        "textContent": text_content
    }

    req = urllib.request.Request(
        url="https://api.brevo.com/v3/smtp/email",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "api-key": BREVO_API_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "VeloTest-Render-OTP-Agent/2.0"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            if res.getcode() in (200, 201, 202):
                logger.info(f"✅ [Brevo API] Successfully delivered OTP [{otp_code}] to {recipient_email}")
                return True
            else:
                body = res.read().decode("utf-8")
                logger.error(f"❌ [Brevo API] HTTP {res.getcode()}: {body}")
                return False
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        logger.error(f"❌ [Brevo API] HTTP {e.code} error: {err_body}")
        return False
    except Exception as e:
        logger.error(f"❌ [Brevo API] Network error: {e}")
        return False


def dispatch_via_gmail_smtp(
    recipient_email: str,
    otp_code: str,
    subject: str,
    text_content: str,
    html_content: str
) -> bool:
    """
    Dispatch email using smtplib SSL (port 465) via Gmail or custom SMTP server.
    """
    if not EMAIL_USER or not EMAIL_PASS:
        logger.error("Gmail SMTP dispatch failed: EMAIL_USER or EMAIL_PASS not configured in .env!")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{APP_NAME} <{EMAIL_USER}>"
    msg["To"] = recipient_email
    msg.set_content(text_content)
    msg.add_alternative(html_content, subtype="html")

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=20) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        logger.info(f"✅ [Gmail SMTP] Successfully delivered OTP [{otp_code}] to {recipient_email}")
        return True
    except Exception as e:
        logger.error(f"❌ [Gmail SMTP] Error dispatching to {recipient_email}: {e}")
        return False


def dispatch_otp_email(
    recipient_email: str,
    otp_code: str,
    log_timestamp: str = "",
    log_message: str = ""
):
    """
    Unified dispatcher: Selects Brevo API or Gmail SMTP based on environment configuration,
    with automatic fallback support. Runs asynchronously in background.
    """
    formatted_time = log_timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    subject = f"🔐 Your VeloTest Verification Code: {otp_code}"

    # Plain text fallback body
    text_content = (
        f"Hello,\n\n"
        f"Your VeloTest verification code is: {otp_code}\n\n"
        f"Generated at: {formatted_time}\n"
        f"Please enter this code on the VeloTest platform to continue.\n"
        f"If you did not request this verification code, please ignore this email.\n\n"
        f"Best regards,\n"
        f"{APP_NAME} Team\n"
    )

    # Modern, responsive HTML Card
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VeloTest Verification Code</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background-color: #f6f9fc;
      margin: 0;
      padding: 24px;
      color: #333333;
    }}
    .container {{
      max-width: 480px;
      margin: 20px auto;
      background: #ffffff;
      border-radius: 12px;
      padding: 36px 28px;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.06);
      border: 1px solid #e9ecef;
    }}
    .brand {{
      text-align: center;
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 1.5px;
      color: #4f46e5;
      text-transform: uppercase;
      margin-bottom: 8px;
    }}
    .heading {{
      text-align: center;
      font-size: 22px;
      font-weight: 700;
      color: #111827;
      margin: 0 0 10px 0;
    }}
    .instructions {{
      text-align: center;
      font-size: 14px;
      color: #6b7280;
      margin: 0 0 24px 0;
      line-height: 1.5;
    }}
    .otp-card {{
      background: #f8fafc;
      border: 2px dashed #6366f1;
      border-radius: 10px;
      padding: 20px;
      text-align: center;
      margin: 20px 0;
    }}
    .otp-number {{
      font-size: 38px;
      font-weight: 800;
      letter-spacing: 8px;
      color: #4338ca;
      font-family: 'Courier New', Courier, monospace;
      margin: 0;
    }}
    .security-notice {{
      background-color: #fffbeb;
      border-left: 4px solid #f59e0b;
      padding: 12px 16px;
      border-radius: 4px;
      font-size: 13px;
      color: #92400e;
      margin-top: 24px;
      line-height: 1.4;
    }}
    .footer {{
      text-align: center;
      font-size: 12px;
      color: #9ca3af;
      margin-top: 28px;
      border-top: 1px solid #f3f4f6;
      padding-top: 16px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">VeloTest Platform</div>
    <h1 class="heading">Verification Code</h1>
    <p class="instructions">Enter the one-time code below to complete verification.</p>

    <div class="otp-card">
      <div class="otp-number">{otp_code}</div>
    </div>

    <div class="security-notice">
      <strong>Security Notice:</strong> Never share this code with anyone. VeloTest staff and exam proctors will never ask for your verification code.
    </div>

    <div class="footer">
      Generated at {formatted_time}<br>
      Automated dispatch via VeloTest Render OTP Agent.
    </div>
  </div>
</body>
</html>"""

    # Provider Selection:
    use_brevo = (EMAIL_PROVIDER == "brevo") or (EMAIL_PROVIDER == "auto" and bool(BREVO_API_KEY))

    if use_brevo:
        logger.info(f"🚀 Dispatching OTP [{otp_code}] to {recipient_email} via Brevo API...")
        success = dispatch_via_brevo(recipient_email, otp_code, subject, text_content, html_content)
        # Automatic fallback to Gmail SMTP if Brevo fails and SMTP credentials exist
        if not success and EMAIL_USER and EMAIL_PASS:
            logger.info("⚠️ Brevo failed; attempting automatic fallback to Gmail SMTP...")
            dispatch_via_gmail_smtp(recipient_email, otp_code, subject, text_content, html_content)
    else:
        logger.info(f"🚀 Dispatching OTP [{otp_code}] to {recipient_email} via Gmail SMTP...")
        dispatch_via_gmail_smtp(recipient_email, otp_code, subject, text_content, html_content)


# ==========================================
# FASTAPI APPLICATION SETUP
# ==========================================
app = FastAPI(
    title="VeloTest Render Real-Time OTP Webhook Agent",
    description="Sub-second OTP log parser and dynamic email dispatcher for VeloTest on Render",
    version="2.1.0"
)


@app.get("/")
@app.head("/")
@app.get("/health")
@app.head("/health")
@app.get("/healthz")
@app.head("/healthz")
def health_check():
    """Dedicated health check endpoint supporting GET and HEAD for uptime monitoring."""
    return {"status": "ok", "service": "render-otp-agent"}


@app.post("/webhook/render-logs")
@app.post("/webhook/logs")
@app.post("/webhook")
async def receive_render_logs(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: Optional[str] = Header(None)
):
    """
    Real-time webhook endpoint receiving log streams from Render Log Drain.
    Accepts JSON arrays, single log entries, NDJSON, and gzip compressed streams.
    Extracts dynamic candidate/user emails & OTP codes, dispatching emails in the background.
    """
    # 1. Optional Webhook Authentication Token Check
    if WEBHOOK_SECRET:
        token = ""
        if authorization and authorization.startswith("Bearer "):
            token = authorization[7:].strip()
        elif authorization:
            token = authorization.strip()

        if token != WEBHOOK_SECRET:
            logger.warning("Unauthorized webhook request rejected.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing Webhook Secret Token"
            )

    # 2. Ingest Payload (Supports JSON object, list of logs, NDJSON, plain text, and gzip)
    try:
        raw_body = await request.body()
        content_encoding = request.headers.get("content-encoding", "").lower()
        if "gzip" in content_encoding:
            try:
                raw_body = gzip.decompress(raw_body)
            except Exception as gz_err:
                logger.warning(f"Gzip decompression error: {gz_err}")

        content_type = request.headers.get("content-type", "").lower()
        logs_to_inspect: List[Dict[str, Any]] = []

        if "application/json" in content_type:
            payload = json.loads(raw_body.decode("utf-8", errors="replace"))

            if isinstance(payload, list):
                logs_to_inspect = payload
            elif isinstance(payload, dict):
                # Standard Render Log Stream formats
                if "logs" in payload and isinstance(payload["logs"], list):
                    logs_to_inspect = payload["logs"]
                elif "logLines" in payload and isinstance(payload["logLines"], list):
                    logs_to_inspect = payload["logLines"]
                elif "events" in payload and isinstance(payload["events"], list):
                    logs_to_inspect = payload["events"]
                else:
                    logs_to_inspect = [payload]
        else:
            # Fallback: Plaintext lines / Syslog / NDJSON
            lines = raw_body.decode("utf-8", errors="replace").splitlines()
            for line in lines:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    obj = json.loads(line_str)
                    if isinstance(obj, dict):
                        logs_to_inspect.append(obj)
                    else:
                        logs_to_inspect.append({"message": line_str})
                except json.JSONDecodeError:
                    logs_to_inspect.append({"message": line_str})

    except Exception as e:
        logger.error(f"Error parsing incoming webhook payload: {e}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Malformed payload", "details": str(e)}
        )

    # 3. Process & Match Log Entries
    matched_count = 0
    dispatched_items = []

    for entry in logs_to_inspect:
        if isinstance(entry, dict):
            message = entry.get("message") or entry.get("text") or entry.get("msg") or str(entry)
            timestamp = entry.get("timestamp") or entry.get("time") or ""
        else:
            message = str(entry)
            timestamp = ""

        # Extract (email, otp)
        result = parse_log_for_email_and_otp(message)
        if result:
            user_email, otp = result

            # Deduplication check
            if is_duplicate(user_email, otp):
                logger.info(f"Duplicate OTP [{otp}] for {user_email} ignored within cache window.")
                continue

            matched_count += 1
            dispatched_items.append({"email": user_email, "otp": otp})

            # Queue non-blocking email dispatch in the background
            background_tasks.add_task(
                dispatch_otp_email,
                recipient_email=user_email,
                otp_code=otp,
                log_timestamp=timestamp,
                log_message=message
            )

    return {
        "status": "success",
        "processed_logs": len(logs_to_inspect),
        "otps_matched": matched_count,
        "dispatched": dispatched_items
    }


# ==========================================
# MANUAL SIMULATION / TEST ENDPOINT
# ==========================================
@app.post("/test-send")
async def test_send(
    email: str,
    otp: str = "593821",
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """
    Test endpoint to simulate email dispatch directly.
    Example: POST /test-send?email=student@example.com&otp=123456
    """
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email query param is required")

    background_tasks.add_task(
        dispatch_otp_email,
        recipient_email=email,
        otp_code=otp,
        log_timestamp=datetime.now(timezone.utc).isoformat(),
        log_message=f"Manual VeloTest test trigger for {email}: {otp}"
    )
    return {"status": "queued", "email": email, "otp": otp}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)
