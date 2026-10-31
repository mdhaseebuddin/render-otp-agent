#!/usr/bin/env python3
"""
Render Real-Time OTP Webhook Receiver & Email Dispatcher
=========================================================
A high-performance, asynchronous FastAPI application that receives real-time
log streams from Render via HTTPS Webhook / Log Drain, dynamically extracts
the target user's email address and OTP code, and dispatches an email
immediately using Gmail SMTP SSL (port 465).

Runs 100% free on Render's Web Service free tier.
"""

import os
import re
import ssl
import json
import time
import logging
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
logger = logging.getLogger("render_otp_webhook")

# ==========================================
# CONFIGURATION
# ==========================================
EMAIL_USER = os.getenv("EMAIL_USER", "").strip()
EMAIL_PASS = os.getenv("EMAIL_PASS", "").strip()
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()
APP_NAME = os.getenv("APP_NAME", "Render OTP Dispatcher").strip()

# Deduplication cache expiration in seconds (default: 300 seconds / 5 mins)
DEDUP_CACHE_TTL = int(os.getenv("DEDUP_CACHE_TTL", "300"))

# In-memory deduplication store: {(email, otp): timestamp}
_recent_dispatches: Dict[Tuple[str, str], float] = {}

# ==========================================
# REGEX PATTERNS FOR EMAIL & OTP
# ==========================================
# Standard RFC 5322 compatible email matcher
EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    re.IGNORECASE
)

# Combined patterns designed to extract (email, otp) or (otp, email)
# Format 1: "OTP sent to user@example.com: 593821" or "code for user@test.com is 123456"
PATTERN_EMAIL_THEN_OTP = re.compile(
    r"(?i)\b(?:otp|verification(?:\s*code)?|security\s*code|auth(?:entication)?\s*code|login\s*code|code)\s*(?:sent\s*to|for|to)?\s*[:=]?\s*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)[^\d\n\r]{1,30}?([0-9]{4,8})\b"
)

# Format 2: "Sent OTP 593821 to user@example.com" or "code: 123456 to user@test.com"
PATTERN_OTP_THEN_EMAIL = re.compile(
    r"(?i)\b(?:otp|verification(?:\s*code)?|security\s*code|auth(?:entication)?\s*code|login\s*code|code)\s*(?:is|:|=|-)?\s*([0-9]{4,8})[^\n\r]*?\b(?:to|for|user|email)\s*[:=]?\s*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b"
)

# Format 3: Key-value / JSON-like: "user: user@example.com ... code: 123456"
PATTERN_KV_EMAIL_OTP = re.compile(
    r"(?i)\b(?:user|email)\s*[:=]\s*['\"]?([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)['\"]?[^\n\r]*?\b(?:otp|code|verification)\s*[:=]\s*['\"]?([0-9]{4,8})['\"]?\b"
)

# Standalone OTP matcher (4-8 digits)
PATTERN_STANDALONE_OTP = re.compile(
    r"(?i)\b(?:otp|verification(?:\s*code)?|security\s*code|auth(?:entication)?\s*code|login\s*code|one[- ]time\s*password|code)\s*(?:is|:|=|-)?\s*['\"]?([0-9]{4,8})['\"]?\b"
)

# User-defined custom regex override (if configured in .env)
CUSTOM_REGEX = os.getenv("OTP_CUSTOM_REGEX", "").strip()
COMPILED_CUSTOM_REGEX = re.compile(CUSTOM_REGEX, re.IGNORECASE) if CUSTOM_REGEX else None


# ==========================================
# PARSER & DEDUPLICATION LOGIC
# ==========================================
def parse_log_for_email_and_otp(message: str) -> Optional[Tuple[str, str]]:
    """
    Inspect a single log line message and extract both target user email and OTP.
    Returns (email, otp) tuple if matched, or None.
    """
    if not message or not isinstance(message, str):
        return None

    # 1. Custom Regex override (if user provided one with named groups or 2 groups)
    if COMPILED_CUSTOM_REGEX:
        custom_match = COMPILED_CUSTOM_REGEX.search(message)
        if custom_match:
            groups = custom_match.groupdict()
            if "email" in groups and "otp" in groups:
                return groups["email"].strip(), groups["otp"].strip()
            elif len(custom_match.groups()) >= 2:
                # Guess order based on @ symbol
                g1, g2 = custom_match.group(1).strip(), custom_match.group(2).strip()
                if "@" in g1:
                    return g1, g2
                return g2, g1

    # 2. Check Pattern: Email then OTP (e.g. "OTP sent to user@example.com: 593821")
    match = PATTERN_EMAIL_THEN_OTP.search(message)
    if match:
        email, otp = match.group(1).strip(), match.group(2).strip()
        return email, otp

    # 3. Check Pattern: OTP then Email (e.g. "Sent OTP 593821 to user@example.com")
    match = PATTERN_OTP_THEN_EMAIL.search(message)
    if match:
        otp, email = match.group(1).strip(), match.group(2).strip()
        return email, otp

    # 4. Check Pattern: Key-Value / Structured format
    match = PATTERN_KV_EMAIL_OTP.search(message)
    if match:
        email, otp = match.group(1).strip(), match.group(2).strip()
        return email, otp

    # 5. Robust Fallback: Log line contains OTP keywords + both an email and a code
    lower_msg = message.lower()
    if any(k in lower_msg for k in ("otp", "verification", "auth code", "login code", "security code", "one-time password")):
        email_match = EMAIL_REGEX.search(message)
        if email_match:
            email = email_match.group(0).strip()
            # Try to find standalone OTP
            otp_match = PATTERN_STANDALONE_OTP.search(message)
            if otp_match:
                return email, otp_match.group(1).strip()
            # As last resort, look for 4-8 digit standalone number
            all_numbers = re.findall(r"\b[0-9]{4,8}\b", message)
            if all_numbers:
                return email, all_numbers[-1].strip()

    return None


def is_duplicate(email: str, otp: str) -> bool:
    """
    Check if the (email, otp) pair was already dispatched within DEDUP_CACHE_TTL.
    Cleans up expired entries periodically.
    """
    now = time.time()
    key = (email.lower(), otp)

    # Periodic cleanup of expired entries
    expired_keys = [k for k, ts in _recent_dispatches.items() if now - ts > DEDUP_CACHE_TTL]
    for k in expired_keys:
        del _recent_dispatches[k]

    if key in _recent_dispatches:
        return True

    _recent_dispatches[key] = now
    return False


# ==========================================
# ASYNC SMTP EMAIL DISPATCHER
# ==========================================
def dispatch_otp_email(recipient_email: str, otp_code: str, log_timestamp: str = "", log_message: str = ""):
    """
    Connect securely via SSL (smtp.gmail.com, port 465) and email the extracted OTP
    directly to the dynamic user email address. Runs in background task.
    """
    if not EMAIL_USER or not EMAIL_PASS:
        logger.error("Cannot dispatch email: EMAIL_USER or EMAIL_PASS is not configured in .env!")
        return

    logger.info(f"🚀 Dispatching OTP [{otp_code}] to user: {recipient_email}")

    formatted_time = log_timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Construct EmailMessage
    msg = EmailMessage()
    msg["Subject"] = f"🔐 Your Verification Code: {otp_code}"
    msg["From"] = f"{APP_NAME} <{EMAIL_USER}>"
    msg["To"] = recipient_email

    # Plain text version
    text_content = (
        f"Hello,\n\n"
        f"Your verification code is: {otp_code}\n\n"
        f"This code was generated at {formatted_time}.\n"
        f"If you did not request this verification code, please ignore this email or secure your account.\n\n"
        f"Best regards,\n"
        f"Security Team\n"
    )
    msg.set_content(text_content)

    # Clean, modern responsive HTML card
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Your Verification Code</title>
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
      font-size: 14px;
      font-weight: 700;
      letter-spacing: 1px;
      color: #6366f1;
      text-transform: uppercase;
      margin-bottom: 8px;
    }}
    .heading {{
      text-align: center;
      font-size: 22px;
      font-weight: 700;
      color: #111827;
      margin: 0 0 12px 0;
    }}
    .instructions {{
      text-align: center;
      font-size: 14px;
      color: #6b7280;
      margin: 0 0 28px 0;
      line-height: 1.5;
    }}
    .otp-card {{
      background: #f8fafc;
      border: 2px dashed #6366f1;
      border-radius: 10px;
      padding: 20px;
      text-align: center;
      margin: 24px 0;
    }}
    .otp-number {{
      font-size: 38px;
      font-weight: 800;
      letter-spacing: 8px;
      color: #4f46e5;
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
    <div class="brand">Authentication Service</div>
    <h1 class="heading">Verification Code</h1>
    <p class="instructions">Use the one-time code below to verify your identity.</p>

    <div class="otp-card">
      <div class="otp-number">{otp_code}</div>
    </div>

    <div class="security-notice">
      <strong>Security Notice:</strong> Never share this code with anyone. Our team will never ask for your code.
    </div>

    <div class="footer">
      Generated at {formatted_time}<br>
      Automated dispatch via Real-Time Render Webhook Agent.
    </div>
  </div>
</body>
</html>"""
    msg.add_alternative(html_content, subtype="html")

    # Connect securely via SSL to smtp.gmail.com:465
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=20) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        logger.info(f"✅ Successfully delivered OTP [{otp_code}] to {recipient_email}!")
    except Exception as e:
        logger.error(f"❌ Failed to dispatch email to {recipient_email}: {e}")


# ==========================================
# FASTAPI APPLICATION SETUP
# ==========================================
app = FastAPI(
    title="Render OTP Real-Time Webhook Agent",
    description="Sub-second OTP log parser and dynamic email dispatcher for Render Log Streams",
    version="2.0.0"
)


@app.get("/")
def root():
    """Root info endpoint."""
    return {
        "status": "online",
        "service": "Render OTP Real-Time Webhook Agent",
        "version": "2.0.0",
        "webhook_endpoint": "/webhook/render-logs",
        "smtp_configured": bool(EMAIL_USER and EMAIL_PASS),
    }


@app.get("/healthz")
def healthz():
    """Health check endpoint for Render service uptime monitoring."""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


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
    Parses dynamic user emails & OTP codes, and triggers background email dispatch.
    """
    # 1. Optional Webhook Authentication
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

    # 2. Ingest Payload (Supports JSON object, list of logs, or raw text)
    try:
        raw_body = await request.body()
        content_type = request.headers.get("content-type", "")

        logs_to_inspect: List[Dict[str, Any]] = []

        if "application/json" in content_type:
            payload = json.loads(raw_body.decode("utf-8", errors="replace"))

            if isinstance(payload, list):
                logs_to_inspect = payload
            elif isinstance(payload, dict):
                # Standard Render Log Stream format: {"logs": [...]} or single entry
                if "logs" in payload and isinstance(payload["logs"], list):
                    logs_to_inspect = payload["logs"]
                else:
                    logs_to_inspect = [payload]
        else:
            # Fallback: Plaintext lines / Syslog / NDJSON
            lines = raw_body.decode("utf-8", errors="replace").splitlines()
            for line in lines:
                line_str = line.strip()
                if not line_str:
                    continue
                # Try parsing each line as individual JSON
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

    # 3. Inspect Log Entries
    matched_count = 0
    dispatched_items = []

    for entry in logs_to_inspect:
        if isinstance(entry, dict):
            message = entry.get("message") or entry.get("text") or str(entry)
            timestamp = entry.get("timestamp") or ""
        else:
            message = str(entry)
            timestamp = ""

        # Extract (email, otp)
        result = parse_log_for_email_and_otp(message)
        if result:
            user_email, otp = result
            # Deduplicate check
            if is_duplicate(user_email, otp):
                logger.info(f"Duplicate OTP [{otp}] for {user_email} detected within cache window. Skipping.")
                continue

            matched_count += 1
            dispatched_items.append({"email": user_email, "otp": otp})

            # Queue immediate asynchronous email delivery in background
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
    Example: POST /test-send?email=your_email@example.com&otp=123456
    """
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email query param is required")

    background_tasks.add_task(
        dispatch_otp_email,
        recipient_email=email,
        otp_code=otp,
        log_timestamp=datetime.now(timezone.utc).isoformat(),
        log_message=f"Manual test trigger for {email}: {otp}"
    )
    return {"status": "queued", "email": email, "otp": otp}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)

