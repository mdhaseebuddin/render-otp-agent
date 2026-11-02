#!/usr/bin/env python3
"""
VeloTest Real-Time OTP Agent
============================
FastAPI application that receives Render Log Streams or direct API requests
and dispatches OTP verification emails via standard Gmail SMTP over SSL.
"""

import os
import re
import ssl
import json
import smtplib
import logging
from typing import Optional, Tuple
from email.message import EmailMessage

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse

# Load environment variables from .env
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
logger = logging.getLogger("velotest_otp_agent")

# ==========================================
# CONFIGURATION
# ==========================================
EMAIL_USER = os.getenv("EMAIL_USER") or os.getenv("SENDER_EMAIL")
EMAIL_PASS = os.getenv("EMAIL_PASS")
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

# Regex patterns for extracting email and OTP
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
OTP_PATTERN = re.compile(
    r"(?i)\b(?:otp|verification(?:\s*code)?|security\s*code|auth(?:entication)?\s*code|login\s*code|code|pin)\b[^\d]{0,25}?(\d{4,8})\b"
)
DIGITS_PATTERN = re.compile(r"\b(\d{4,8})\b")


# ==========================================
# SMTP EMAIL DISPATCHER
# ==========================================
def send_otp_via_smtp(to_email: str, otp_code: str):
    """
    Connect to smtp.gmail.com on port 465 using smtplib.SMTP_SSL,
    authenticate with EMAIL_USER and EMAIL_PASS, and send an email
    with the subject 'Your VeloTest Verification Code'.
    """
    user = os.getenv("EMAIL_USER") or os.getenv("SENDER_EMAIL")
    password = os.getenv("EMAIL_PASS")

    if not user or not password:
        error_msg = "EMAIL_USER (or SENDER_EMAIL) and EMAIL_PASS must be configured in environment."
        logger.error(f"[ERROR] {error_msg}")
        raise RuntimeError(error_msg)

    msg = EmailMessage()
    msg["Subject"] = "Your VeloTest Verification Code"
    msg["From"] = f"VeloTest <{user}>"
    msg["To"] = to_email

    # Plain text fallback body
    msg.set_content(
        f"Your VeloTest verification code is: {otp_code}\n\n"
        f"This code is valid for 2 minutes. Do not share this code with anyone.\n"
    )

    # Clean HTML body
    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f6f9fc; margin: 0; padding: 24px; }}
    .card {{ max-width: 480px; margin: 20px auto; background: #ffffff; border-radius: 12px; padding: 36px 28px; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.06); border: 1px solid #e9ecef; text-align: center; }}
    .brand {{ font-size: 13px; font-weight: 700; letter-spacing: 1.5px; color: #4f46e5; text-transform: uppercase; margin-bottom: 8px; }}
    .title {{ font-size: 22px; font-weight: 700; color: #111827; margin: 0 0 10px 0; }}
    .instructions {{ font-size: 14px; color: #6b7280; margin: 0 0 24px 0; }}
    .otp-card {{ background: #f8fafc; border: 2px dashed #6366f1; border-radius: 10px; padding: 18px; text-align: center; margin: 20px 0; }}
    .otp-number {{ font-size: 38px; font-weight: 800; letter-spacing: 8px; color: #4338ca; font-family: 'Courier New', Courier, monospace; margin: 0; }}
    .validity-notice {{ background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px 16px; border-radius: 4px; font-size: 13px; color: #92400e; margin-top: 24px; text-align: left; }}
    .footer {{ font-size: 12px; color: #9ca3af; margin-top: 28px; border-top: 1px solid #f3f4f6; padding-top: 16px; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="brand">VeloTest Security</div>
    <h1 class="title">Verification Code</h1>
    <p class="instructions">Please enter the code below to complete your verification:</p>
    <div class="otp-card">
      <div class="otp-number">{otp_code}</div>
    </div>
    <div class="validity-notice">
      ⏱️ <strong>Note:</strong> This verification code is valid for <strong>2 minutes</strong>. Never share this code with anyone.
    </div>
    <div class="footer">If you did not request this verification code, please ignore this email.</div>
  </div>
</body>
</html>"""
    msg.add_alternative(html_content, subtype="html")

    logger.info(f"Connecting to {SMTP_HOST}:{SMTP_PORT} via SSL to email {to_email}...")
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15) as server:
        server.login(user, password)
        server.send_message(msg)

    logger.info(f"✅ [SMTP SSL] Successfully sent OTP [{otp_code}] to {to_email}")


# ==========================================
# PARSER HELPER
# ==========================================
def extract_recipient_and_otp(text: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract the recipient email and OTP code from a log string using regex.
    Detects patterns like 'OTP: <digits>' or mentions of 'mdhaseebuddin24@gmail.com'.
    """
    if not text:
        return None, None

    lower_text = text.lower()
    has_otp_indicator = bool(OTP_PATTERN.search(text)) or ("otp" in lower_text)
    has_target_email = "mdhaseebuddin24@gmail.com" in lower_text

    if not has_otp_indicator and not has_target_email:
        return None, None

    # 1. Extract recipient email
    recipient = None
    email_match = EMAIL_REGEX.search(text)
    if email_match:
        recipient = email_match.group(0).strip()
    elif has_target_email:
        recipient = "mdhaseebuddin24@gmail.com"
    else:
        # Default fallback target if OTP is present without explicit email
        recipient = "mdhaseebuddin24@gmail.com"

    # 2. Extract OTP code
    otp = None
    otp_match = OTP_PATTERN.search(text)
    if otp_match:
        otp = otp_match.group(1).strip()
    else:
        # Look for standalone 4-8 digit numbers excluding numbers inside the email
        text_without_email = text.replace(recipient, "") if recipient else text
        digits = DIGITS_PATTERN.findall(text_without_email)
        if digits:
            otp = digits[-1].strip()

    if recipient and otp:
        return recipient, otp

    return None, None


# ==========================================
# FASTAPI APPLICATION SETUP
# ==========================================
app = FastAPI(title="VeloTest OTP Agent", version="4.0.0")


@app.get("/")
@app.head("/")
def root():
    return {"status": "ok", "service": "VeloTest OTP Agent"}


@app.get("/health")
@app.head("/health")
@app.get("/healthz")
@app.head("/healthz")
def health():
    return {"status": "ok"}


@app.post("/webhook/render-logs")
@app.post("/webhook/logs")
@app.post("/webhook")
async def webhook_render_logs(request: Request):
    """
    Parse the incoming JSON log string. If it detects an OTP pattern (e.g. OTP: <digits>)
    or 'mdhaseebuddin24@gmail.com', extract the recipient email and OTP code using regex,
    call send_otp_via_smtp, and return {"status": "success", "message": f"OTP {otp} sent to {recipient}"}.
    If no OTP pattern matches, return {"status": "ignored"}.
    """
    try:
        raw_body = await request.body()
        body_text = raw_body.decode("utf-8", errors="replace")
    except Exception as e:
        logger.error(f"[ERROR] Failed to read request body: {e}")
        return JSONResponse(status_code=400, content={"error": "Invalid body"})

    # Extract log messages from payload (supports dict, list, logs array, or plain string)
    log_candidates = []
    try:
        data = json.loads(body_text)
        if isinstance(data, dict):
            if "logs" in data and isinstance(data["logs"], list):
                for item in data["logs"]:
                    if isinstance(item, dict):
                        log_candidates.append(item.get("message") or item.get("text") or str(item))
                    else:
                        log_candidates.append(str(item))
            elif "message" in data:
                log_candidates.append(str(data["message"]))
            else:
                log_candidates.append(body_text)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    log_candidates.append(item.get("message") or item.get("text") or str(item))
                else:
                    log_candidates.append(str(item))
        elif isinstance(data, str):
            log_candidates.append(data)
    except Exception:
        log_candidates.append(body_text)

    # Search for an OTP pattern or target email
    for log_msg in log_candidates:
        recipient, otp = extract_recipient_and_otp(log_msg)
        if recipient and otp:
            logger.info(f"Matched OTP [{otp}] for recipient [{recipient}] in log.")
            try:
                send_otp_via_smtp(to_email=recipient, otp_code=otp)
                return {
                    "status": "success",
                    "message": f"OTP {otp} sent to {recipient}"
                }
            except Exception as e:
                logger.error(f"[ERROR] Failed sending OTP via SMTP: {e}")
                raise HTTPException(status_code=500, detail=str(e))

    return {"status": "ignored"}


@app.post("/send-otp")
async def send_otp(request: Request):
    """
    Expect {"email": "...", "otp": "..."}, validate both fields exist (HTTP 400 if missing),
    call send_otp_via_smtp, and return success.
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Payload must be a JSON object")

    email = data.get("email")
    otp = data.get("otp")

    if not email or not otp:
        raise HTTPException(status_code=400, detail="Both 'email' and 'otp' fields are required")

    email_str = str(email).strip()
    otp_str = str(otp).strip()

    try:
        send_otp_via_smtp(to_email=email_str, otp_code=otp_str)
        return {
            "status": "success",
            "message": f"OTP {otp_str} sent to {email_str}"
        }
    except Exception as e:
        logger.error(f"[ERROR] send_otp endpoint failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)
