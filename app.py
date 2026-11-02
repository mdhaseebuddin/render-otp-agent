#!/usr/bin/env python3
"""
Render Real-Time OTP Webhook Receiver & Brevo HTTPS Email Dispatcher
=====================================================================
A high-performance, asynchronous FastAPI application that receives real-time
log streams from Render via HTTPS Webhook / Log Drain, dynamically extracts
the target user's email address and OTP code, and dispatches verification
emails exclusively over HTTPS REST API (Port 443) using Brevo v3.

Bypasses all outbound raw SMTP port blocks (465/587) on Render Free Tier.
"""

import os
import re
import gzip
import json
import time
import logging
from typing import Optional, Tuple, List, Dict, Any
from datetime import datetime, timezone
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
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"

# Webhook Security & App Settings
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "").strip()
APP_NAME = os.environ.get("APP_NAME", "VeloTest Security").strip()
DEDUP_CACHE_TTL = int(os.environ.get("DEDUP_CACHE_TTL", "300"))

# In-memory deduplication store: {(email, otp): timestamp}
_recent_dispatches: Dict[Tuple[str, str], float] = {}


def get_brevo_api_key() -> str:
    """Retrieve Brevo API key from primary or secondary environment variable."""
    return (
        os.environ.get("BREVO_API_KEY", "").strip()
        or os.environ.get("BREVO_API_KEY_FALLBACK", "").strip()
        or os.environ.get("BREVO_KEY", "").strip()
        or os.environ.get("SENDINBLUE_API_KEY", "").strip()
    )


def get_sender() -> dict:
    """Retrieve sender configuration with environment variable overrides."""
    sender_email = (
        os.environ.get("SENDER_EMAIL", "").strip()
        or os.environ.get("BREVO_SENDER_EMAIL", "").strip()
        or "mdhaseebuddin24@gmail.com"
    )
    sender_name = os.environ.get("SENDER_NAME", "").strip() or "VeloTest Security"
    return {"name": sender_name, "email": sender_email}


# ==========================================
# REGEX PATTERNS FOR EMAIL & OTP
# ==========================================
EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    re.IGNORECASE
)

# Pattern 1: Email then OTP ("OTP sent to user@example.com: 593821")
PATTERN_EMAIL_THEN_OTP = re.compile(
    r"(?i)\b(?:otp|verification(?:\s*code)?|security\s*code|auth(?:entication)?\s*code|login\s*code|passcode|token|pin|code)\s*(?:sent\s*to|for|to|user|student|candidate)?\s*[:=]?\s*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)[^\d\n\r]{1,35}?([0-9]{4,8})\b"
)

# Pattern 2: OTP then Email ("Sent OTP 593821 to user@example.com")
PATTERN_OTP_THEN_EMAIL = re.compile(
    r"(?i)\b(?:otp|verification(?:\s*code)?|security\s*code|auth(?:entication)?\s*code|login\s*code|passcode|token|pin|code)\s*(?:is|:|=|-)?\s*([0-9]{4,8})[^\n\r]*?\b(?:to|for|user|student|candidate|email)\s*[:=]?\s*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b"
)

# Pattern 3: Key-Value structured format ("user: user@example.com | otp: 123456")
PATTERN_KV_EMAIL_OTP = re.compile(
    r"(?i)\b(?:user|email|student|candidate|recipient|to)\s*[:=]\s*['\"]?([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)['\"]?[^\n\r]*?\b(?:otp|code|verification|passcode|pin|token)\s*[:=]\s*['\"]?([0-9]{4,8})['\"]?\b"
)

# Standalone OTP matcher (4 to 8 digits)
PATTERN_STANDALONE_OTP = re.compile(
    r"(?i)\b(?:otp|verification(?:\s*code)?|security\s*code|auth(?:entication)?\s*code|login\s*code|one[- ]time\s*password|passcode|pin|token|code)\s*(?:is|:|=|-)?\s*['\"]?([0-9]{4,8})['\"]?\b"
)

# Optional user-defined custom regex override
CUSTOM_REGEX = os.environ.get("OTP_CUSTOM_REGEX", "").strip()
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
# BREVO HTTPS REST EMAIL DISPATCHER
# ==========================================
def generate_otp_html(otp_code: str) -> str:
    """
    Generate clean, responsive HTML email containing the OTP code
    and a prominent 2-minute validity note.
    """
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
    <div class="brand">VeloTest Security</div>
    <h1 class="heading">Verification Code</h1>
    <p class="instructions">Please enter the one-time verification code below to complete your login.</p>

    <div class="otp-card">
      <div class="otp-number">{otp_code}</div>
    </div>

    <div class="validity-notice">
      ⏱️ <strong>Note:</strong> This verification code is valid for <strong>2 minutes</strong>. Never share this code with anyone. VeloTest staff and exam proctors will never ask for your verification code.
    </div>

    <div class="footer">
      If you did not request this verification code, please ignore this email or secure your account.<br>
      Automated dispatch via VeloTest Security.
    </div>
  </div>
</body>
</html>"""


def dispatch_via_brevo(recipient_email: str, otp_code: str) -> dict:
    """
    Dispatch transactional email via Brevo REST API (HTTPS port 443).
    Logs the Brevo response and returns a structured response dict with HTTP status.
    """
    brevo_api_key = get_brevo_api_key()
    if not brevo_api_key:
        error_msg = "Brevo dispatch failed: BREVO_API_KEY is not configured in environment variables!"
        logger.error(error_msg)
        return {"status_code": 500, "success": False, "error": error_msg}

    sender = get_sender()
    html_content = generate_otp_html(otp_code)

    headers = {
        "accept": "application/json",
        "api-key": brevo_api_key,
        "content-type": "application/json"
    }

    payload = {
        "sender": sender,
        "to": [{"email": recipient_email}],
        "subject": "Your Verification Code",
        "htmlContent": html_content
    }

    try:
        response = requests.post(
            BREVO_API_URL,
            headers=headers,
            json=payload,
            timeout=15
        )

        try:
            resp_json = response.json()
        except Exception:
            resp_json = {"raw": response.text}

        logger.info(
            f"Brevo API Response Status: {response.status_code} | Output: {json.dumps(resp_json)}"
        )

        if response.status_code in (200, 201, 202):
            logger.info(f"✅ Successfully delivered OTP [{otp_code}] to {recipient_email} via Brevo API")
            return {
                "status_code": 200,
                "success": True,
                "brevo_status": response.status_code,
                "response": resp_json
            }
        else:
            error_msg = f"Brevo API error (HTTP {response.status_code}): {resp_json}"
            logger.error(f"❌ {error_msg}")
            return {
                "status_code": 500,
                "success": False,
                "error": error_msg,
                "brevo_status": response.status_code,
                "response": resp_json
            }

    except requests.exceptions.RequestException as e:
        error_msg = f"Network exception connecting to Brevo API: {str(e)}"
        logger.error(f"❌ {error_msg}")
        return {
            "status_code": 500,
            "success": False,
            "error": error_msg
        }
    except Exception as e:
        error_msg = f"Unexpected error during Brevo dispatch: {str(e)}"
        logger.error(f"❌ {error_msg}")
        return {
            "status_code": 500,
            "success": False,
            "error": error_msg
        }


def dispatch_otp_email(
    recipient_email: str,
    otp_code: str,
    log_timestamp: str = "",
    log_message: str = ""
) -> dict:
    """
    Background worker function to dispatch OTP via Brevo HTTPS REST API.
    Does not crash on failure and logs exact response details.
    """
    logger.info(f"🚀 Dispatching OTP [{otp_code}] to {recipient_email} via Brevo HTTPS API...")
    return dispatch_via_brevo(recipient_email=recipient_email, otp_code=otp_code)


# ==========================================
# FASTAPI APPLICATION SETUP
# ==========================================
app = FastAPI(
    title="VeloTest Render Real-Time OTP Webhook Agent",
    description="Sub-second OTP log parser and Brevo HTTPS email dispatcher for VeloTest on Render",
    version="2.2.0"
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
    background_tasks: BackgroundTasks,
    authorization: Optional[str] = Header(None)
):
    """
    Real-time webhook endpoint receiving log streams from Render Log Drain.
    Accepts JSON arrays, single log entries, NDJSON, and gzip compressed streams.
    Extracts dynamic candidate/user emails & OTP codes, dispatching emails over Brevo HTTPS.
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
# MANUAL SIMULATION / TEST DISPATCH ENDPOINT
# ==========================================
@app.post("/test-send")
async def test_send(
    email: str,
    otp: str = "593821"
):
    """
    Direct test endpoint to simulate and verify Brevo HTTPS email dispatch.
    Returns HTTP 200 on success (Brevo 200, 201, 202) or HTTP 500 on failure without crashing.
    Example: POST /test-send?email=candidate@example.com&otp=123456
    """
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email query param is required")

    result = dispatch_via_brevo(recipient_email=email, otp_code=otp)
    if result.get("status_code") == 200:
        return JSONResponse(status_code=status.HTTP_200_OK, content=result)
    else:
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=result)


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)
