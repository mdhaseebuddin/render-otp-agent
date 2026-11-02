#!/usr/bin/env python3
"""
Render Real-Time OTP Webhook Receiver & Gmail REST API Dispatcher
=================================================================
A high-performance FastAPI application that receives real-time log streams
from Render via HTTPS Webhook / Log Drain, dynamically extracts the target
user's email address and OTP code, and dispatches verification emails
exclusively via the official Google Gmail REST API over HTTPS (Port 443).

Completely bypasses raw SMTP ports (465/587) using OAuth2 access token refresh.
"""

import os
import re
import gzip
import json
import time
import base64
import logging
from typing import Optional, Tuple, List, Dict, Any
from datetime import datetime, timezone
from email.message import EmailMessage

import requests
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
# CONFIGURATION & CONSTANTS
# ==========================================
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_SEND_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "").strip()
APP_NAME = os.environ.get("APP_NAME", "VeloTest").strip()
DEDUP_CACHE_TTL = int(os.environ.get("DEDUP_CACHE_TTL", "300"))

# In-memory deduplication store: {(email, otp): timestamp}
_recent_dispatches: Dict[Tuple[str, str], float] = {}

# In-memory OAuth2 token cache
_cached_access_token: Optional[str] = None
_token_expiry_timestamp: float = 0.0


# ==========================================
# OAUTH2 ACCESS TOKEN REFRESH
# ==========================================
def get_gmail_access_token() -> str:
    """
    Request a fresh short-lived OAuth2 access token from Google using the refresh token.
    Caches the token in-memory until near expiration.
    """
    global _cached_access_token, _token_expiry_timestamp

    now = time.time()
    if _cached_access_token and now < (_token_expiry_timestamp - 60):
        return _cached_access_token

    client_id = os.environ.get("GMAIL_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GMAIL_CLIENT_SECRET", "").strip()
    refresh_token = os.environ.get("GMAIL_REFRESH_TOKEN", "").strip()

    missing = []
    if not client_id:
        missing.append("GMAIL_CLIENT_ID")
    if not client_secret:
        missing.append("GMAIL_CLIENT_SECRET")
    if not refresh_token:
        missing.append("GMAIL_REFRESH_TOKEN")

    if missing:
        raise RuntimeError(
            f"Missing required Gmail OAuth2 environment variables: {', '.join(missing)}"
        )

    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }

    try:
        response = requests.post(GOOGLE_TOKEN_URL, data=payload, timeout=10)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Network error connecting to Google OAuth2 token endpoint: {e}")

    try:
        token_data = response.json()
    except Exception:
        token_data = {}

    if response.status_code != 200 or "access_token" not in token_data:
        raise RuntimeError(
            f"Failed to refresh Google OAuth2 access token (HTTP {response.status_code}): {response.text}"
        )

    access_token = token_data["access_token"]
    expires_in = int(token_data.get("expires_in", 3600))

    _cached_access_token = access_token
    _token_expiry_timestamp = now + expires_in

    return access_token


# ==========================================
# EMAIL CONSTRUCTION & DISPATCH
# ==========================================
def generate_otp_html(otp_code: str) -> str:
    """Generate clean, responsive HTML email displaying the OTP code with 2-minute validity note."""
    return f"""<!DOCTYPE html>
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
    .validity-notice {{
      background-color: #fef3c7;
      border-left: 4px solid #f59e0b;
      padding: 12px 16px;
      border-radius: 4px;
      font-size: 13px;
      color: #92400e;
      margin-top: 24px;
      line-height: 1.5;
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
    <div class="brand">VeloTest</div>
    <h1 class="heading">Verification Code</h1>
    <p class="instructions">Please enter the one-time verification code below to complete your verification.</p>

    <div class="otp-card">
      <div class="otp-number">{otp_code}</div>
    </div>

    <div class="validity-notice">
      ⏱️ <strong>Note:</strong> This verification code is valid for <strong>2 minutes</strong>. Never share this code with anyone. VeloTest staff and exam proctors will never ask for your verification code.
    </div>

    <div class="footer">
      If you did not request this verification code, please ignore this email or secure your account.<br>
      Automated dispatch via VeloTest Authentication Service.
    </div>
  </div>
</body>
</html>"""


def dispatch_gmail_rest_email(recipient_email: str, otp_code: str) -> dict:
    """
    Construct an RFC 2822 email, base64url encode it, and dispatch via Gmail REST API.
    Raises RuntimeError on any failure.
    """
    sender_email = os.environ.get("SENDER_EMAIL", "velotest2026@gmail.com").strip() or "velotest2026@gmail.com"

    # 1. Fetch valid OAuth2 access token
    access_token = get_gmail_access_token()

    # 2. Construct RFC 2822 Email Message
    msg = EmailMessage()
    msg["Subject"] = "Your Verification Code"
    msg["From"] = f"VeloTest <{sender_email}>"
    msg["To"] = recipient_email
    msg.set_content(f"Your verification code is: {otp_code}\nExpires in 2 minutes.")
    msg.add_alternative(generate_otp_html(otp_code), subtype="html")

    # 3. Base64url encode raw bytes
    raw_bytes = msg.as_bytes()
    encoded_raw_message = base64.urlsafe_b64encode(raw_bytes).decode("utf-8")

    # 4. Dispatch via Gmail REST API
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload = {"raw": encoded_raw_message}

    try:
        response = requests.post(GMAIL_SEND_URL, headers=headers, json=payload, timeout=10)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Network error connecting to Gmail REST API: {e}")

    if response.status_code not in (200, 201):
        raise RuntimeError(
            f"Gmail API dispatch failed (HTTP {response.status_code}): {response.text}"
        )

    try:
        res_json = response.json()
    except Exception:
        res_json = {"raw": response.text}

    logger.info(
        f"✅ [Gmail REST API] Delivered OTP [{otp_code}] to {recipient_email}. Message ID: {res_json.get('id')}"
    )
    return res_json


# ==========================================
# REGEX PATTERNS FOR EMAIL & OTP
# ==========================================
EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    re.IGNORECASE
)

PATTERN_EMAIL_THEN_OTP = re.compile(
    r"(?i)\b(?:otp|verification(?:\s*code)?|security\s*code|auth(?:entication)?\s*code|login\s*code|passcode|token|pin|code)\s*(?:sent\s*to|for|to|user|student|candidate)?\s*[:=]?\s*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)[^\d\n\r]{1,35}?([0-9]{4,8})\b"
)

PATTERN_OTP_THEN_EMAIL = re.compile(
    r"(?i)\b(?:otp|verification(?:\s*code)?|security\s*code|auth(?:entication)?\s*code|login\s*code|passcode|token|pin|code)\s*(?:is|:|=|-)?\s*([0-9]{4,8})[^\n\r]*?\b(?:to|for|user|student|candidate|email)\s*[:=]?\s*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b"
)

PATTERN_KV_EMAIL_OTP = re.compile(
    r"(?i)\b(?:user|email|student|candidate|recipient|to)\s*[:=]\s*['\"]?([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)['\"]?[^\n\r]*?\b(?:otp|code|verification|passcode|pin|token)\s*[:=]\s*['\"]?([0-9]{4,8})['\"]?\b"
)

PATTERN_STANDALONE_OTP = re.compile(
    r"(?i)\b(?:otp|verification(?:\s*code)?|security\s*code|auth(?:entication)?\s*code|login\s*code|one[- ]time\s*password|passcode|pin|token|code)\s*(?:is|:|=|-)?\s*['\"]?([0-9]{4,8})['\"]?\b"
)

CUSTOM_REGEX = os.environ.get("OTP_CUSTOM_REGEX", "").strip()
COMPILED_CUSTOM_REGEX = re.compile(CUSTOM_REGEX, re.IGNORECASE) if CUSTOM_REGEX else None


# ==========================================
# PARSER & DEDUPLICATION LOGIC
# ==========================================
def parse_log_for_email_and_otp(message: str) -> Optional[Tuple[str, str]]:
    """Inspect a single log line message and extract both target user email and OTP."""
    if not message or not isinstance(message, str):
        return None

    cleaned_msg = message.strip()

    # 1. Embedded JSON inspection
    if "{" in cleaned_msg and "}" in cleaned_msg:
        try:
            start_idx = cleaned_msg.find("{")
            end_idx = cleaned_msg.rfind("}") + 1
            json_str = cleaned_msg[start_idx:end_idx]
            data = json.loads(json_str)
            if isinstance(data, dict):
                email_val = None
                for ek in ("email", "user", "student", "candidate", "recipient", "to", "user_email", "student_email"):
                    if ek in data and isinstance(data[ek], str) and "@" in data[ek]:
                        email_val = data[ek].strip()
                        break

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

    # 3. Check Pattern: Email then OTP
    match = PATTERN_EMAIL_THEN_OTP.search(cleaned_msg)
    if match:
        email, otp = match.group(1).strip(), match.group(2).strip()
        return email, otp

    # 4. Check Pattern: OTP then Email
    match = PATTERN_OTP_THEN_EMAIL.search(cleaned_msg)
    if match:
        otp, email = match.group(1).strip(), match.group(2).strip()
        return email, otp

    # 5. Check Pattern: Structured Key-Value
    match = PATTERN_KV_EMAIL_OTP.search(cleaned_msg)
    if match:
        email, otp = match.group(1).strip(), match.group(2).strip()
        return email, otp

    # 6. Universal Heuristic Fallback
    lower_msg = cleaned_msg.lower()
    otp_indicators = (
        "otp", "verification", "verify", "auth", "login",
        "code", "pin", "passcode", "token", "velotest", "exam"
    )
    if any(k in lower_msg for k in otp_indicators):
        email_match = EMAIL_REGEX.search(cleaned_msg)
        if email_match:
            candidate_email = email_match.group(0).strip()
            otp_match = PATTERN_STANDALONE_OTP.search(cleaned_msg)
            if otp_match:
                return candidate_email, otp_match.group(1).strip()
            msg_without_email = cleaned_msg.replace(candidate_email, "")
            digits = re.findall(r"\b[0-9]{4,8}\b", msg_without_email)
            if digits:
                return candidate_email, digits[-1].strip()

    return None


def is_duplicate(email: str, otp: str) -> bool:
    """Check if the (email, otp) pair was already dispatched within DEDUP_CACHE_TTL."""
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
# FASTAPI APPLICATION SETUP
# ==========================================
app = FastAPI(
    title="VeloTest Render Real-Time OTP Webhook Agent",
    description="Sub-second OTP log parser and Gmail REST API email dispatcher for VeloTest on Render",
    version="3.0.0"
)


# Dedicated Health Check routes supporting GET and HEAD
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
    authorization: Optional[str] = Header(None)
):
    """
    Real-time webhook endpoint receiving log streams from Render Log Drain.
    Parses dynamic candidate/user emails & OTP codes, and invokes the Gmail REST API dispatcher.
    Returns HTTP 200 with status: success and channel: gmail_rest_api.
    Catches exceptions safely, logs [ERROR] Gmail API dispatch failed: <err>, and returns HTTP 500 without crashing.
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
                if "logs" in payload and isinstance(payload["logs"], list):
                    logs_to_inspect = payload["logs"]
                elif "logLines" in payload and isinstance(payload["logLines"], list):
                    logs_to_inspect = payload["logLines"]
                elif "events" in payload and isinstance(payload["events"], list):
                    logs_to_inspect = payload["events"]
                else:
                    logs_to_inspect = [payload]
        else:
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
        else:
            message = str(entry)

        # Extract (email, otp)
        result = parse_log_for_email_and_otp(message)
        if result:
            user_email, otp = result

            # Deduplication check
            if is_duplicate(user_email, otp):
                logger.info(f"Duplicate OTP [{otp}] for {user_email} ignored within cache window.")
                continue

            matched_count += 1
            logger.info(f"🚀 Invoking Gmail REST API dispatcher for {user_email} (OTP: {otp})...")

            try:
                dispatch_res = dispatch_gmail_rest_email(recipient_email=user_email, otp_code=otp)
                dispatched_items.append({
                    "email": user_email,
                    "otp": otp,
                    "message_id": dispatch_res.get("id")
                })
            except Exception as err:
                logger.error(f"[ERROR] Gmail API dispatch failed: {err}")
                return JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content={
                        "status": "error",
                        "channel": "gmail_rest_api",
                        "detail": str(err)
                    }
                )

    return {
        "status": "success",
        "channel": "gmail_rest_api",
        "processed_logs": len(logs_to_inspect),
        "otps_matched": matched_count,
        "dispatched": dispatched_items
    }


# ==========================================
# MANUAL SIMULATION / TEST DISPATCH ENDPOINT
# ==========================================
@app.post("/test-send")
async def test_send(
    email: str,
    otp: str = "593821"
):
    """
    Direct test endpoint to simulate and verify Gmail REST API email dispatch.
    Returns HTTP 200 on success or HTTP 500 on failure without crashing the server.
    Example: POST /test-send?email=candidate@example.com&otp=123456
    """
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email query param is required")

    try:
        dispatch_res = dispatch_gmail_rest_email(recipient_email=email, otp_code=otp)
        return {
            "status": "success",
            "channel": "gmail_rest_api",
            "email": email,
            "otp": otp,
            "message_id": dispatch_res.get("id")
        }
    except Exception as err:
        logger.error(f"[ERROR] Gmail API dispatch failed: {err}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "channel": "gmail_rest_api",
                "detail": str(err)
            }
        )


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)
