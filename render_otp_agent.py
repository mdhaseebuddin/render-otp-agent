#!/usr/bin/env python3
"""
Render OTP Agent
================
A lightweight, free, and robust Python script that polls Render service logs,
extracts One-Time Passwords (OTPs) and verification codes using regex, and
dispatches them immediately to your email via Gmail SMTP SSL.

Author: Antigravity Agent
"""

import os
import sys
import re
import ssl
import json
import time
import argparse
import smtplib
from datetime import datetime, timezone
import urllib.request
import urllib.error
import urllib.parse
from email.message import EmailMessage

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # Fallback if python-dotenv is not yet installed
    pass

# ==========================================
# CONFIGURATION
# ==========================================
RENDER_API_KEY = os.getenv("RENDER_API_KEY", "").strip()
RENDER_SERVICE_ID = os.getenv("RENDER_SERVICE_ID", "").strip()
RENDER_OWNER_ID = os.getenv("RENDER_OWNER_ID", "").strip()

EMAIL_USER = os.getenv("EMAIL_USER", "").strip()
EMAIL_PASS = os.getenv("EMAIL_PASS", "").strip()
RECIPIENT_EMAIL = os.getenv("RECIPIENT_EMAIL", "").strip()

# State file to prevent duplicate email alerts
STATE_FILE = os.getenv("STATE_FILE", "last_processed.txt")

# Polling interval in seconds when running in loop mode
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SECONDS", "15"))

# Render API Base URL
RENDER_API_BASE = "https://api.render.com/v1"

# Default regex patterns for matching OTP / Verification codes
# Matches:
#   "OTP is 123456"
#   "Verification code: 987654"
#   "Your OTP is 123456"
#   "Security code: 123456"
#   "Code: 123456"
#   "Auth code: 123456"
#   "One-time password: 123456"
CUSTOM_REGEX = os.getenv("OTP_REGEX_PATTERN", "").strip()
if CUSTOM_REGEX:
    OTP_PATTERNS = [re.compile(CUSTOM_REGEX, re.IGNORECASE)]
else:
    OTP_PATTERNS = [
        re.compile(
            r"(?i)\b(?:otp|verification\s*code|security\s*code|auth(?:entication)?\s*code|login\s*code|one[- ]time\s*password)\s*(?:is|:|=|-)?\s*['\"]?([0-9]{4,8})['\"]?\b"
        ),
        re.compile(
            r"(?i)\b(?:your\s+code\s+is|code\s*[:=])\s*['\"]?([0-9]{4,8})['\"]?\b"
        ),
    ]


# ==========================================
# HELPER FUNCTIONS
# ==========================================
def validate_config(require_email=True):
    """Validate that required environment variables are set."""
    missing = []
    if not RENDER_API_KEY:
        missing.append("RENDER_API_KEY")
    if not RENDER_SERVICE_ID:
        missing.append("RENDER_SERVICE_ID")

    if require_email:
        if not EMAIL_USER:
            missing.append("EMAIL_USER")
        if not EMAIL_PASS:
            missing.append("EMAIL_PASS")
        if not RECIPIENT_EMAIL:
            missing.append("RECIPIENT_EMAIL")

    if missing:
        print(f"[ERROR] Missing required configuration in .env: {', '.join(missing)}")
        print("Please check your .env file or environment variables.")
        sys.exit(1)


def read_last_processed() -> str:
    """Read the last processed timestamp or log identifier from the state file."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip()
                return content
        except Exception as e:
            print(f"[WARN] Could not read {STATE_FILE}: {e}")
    return ""


def save_last_processed(marker: str):
    """Persist the last processed timestamp or log identifier to the state file."""
    if not marker:
        return
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            f.write(marker.strip() + "\n")
    except Exception as e:
        print(f"[ERROR] Failed to save state to {STATE_FILE}: {e}")


def render_http_get(endpoint: str, params: dict = None) -> dict:
    """Make an authenticated GET request to the Render REST API using urllib."""
    url = f"{RENDER_API_BASE}/{endpoint.lstrip('/')}"
    if params:
        clean_params = {k: v for k, v in params.items() if v is not None and str(v).strip() != ""}
        if clean_params:
            query_string = urllib.parse.urlencode(clean_params)
            url = f"{url}?{query_string}"

    req = urllib.request.Request(
        url=url,
        headers={
            "Authorization": f"Bearer {RENDER_API_KEY}",
            "Accept": "application/json",
            "User-Agent": "RenderOTPAgent/1.0"
        },
        method="GET"
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            status_code = response.getcode()
            body = response.read().decode("utf-8")
            if status_code == 200:
                return json.loads(body)
            else:
                print(f"[WARN] Render API returned status {status_code}: {body}")
                return {}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        print(f"[ERROR] HTTP {e.code} error fetching '{url}': {error_body}")
        raise
    except urllib.error.URLError as e:
        print(f"[ERROR] Network error contacting Render API: {e.reason}")
        raise


def get_owner_id() -> str:
    """
    Fetch the workspace ownerId for the service if not provided in environment.
    Render's /v1/logs requires ownerId as a parameter.
    """
    global RENDER_OWNER_ID
    if RENDER_OWNER_ID:
        return RENDER_OWNER_ID

    print(f"[*] Querying service details for {RENDER_SERVICE_ID} to resolve ownerId...")
    try:
        service_data = render_http_get(f"services/{RENDER_SERVICE_ID}")
        # The response format can be {"service": {"ownerId": "..."}} or {"ownerId": "..."}
        if "service" in service_data and isinstance(service_data["service"], dict):
            RENDER_OWNER_ID = service_data["service"].get("ownerId", "")
        else:
            RENDER_OWNER_ID = service_data.get("ownerId", "")

        if RENDER_OWNER_ID:
            print(f"[+] Found Owner ID: {RENDER_OWNER_ID}")
            return RENDER_OWNER_ID
    except Exception as e:
        print(f"[WARN] Could not retrieve ownerId automatically: {e}")

    return ""


def fetch_render_logs(limit: int = 100) -> list:
    """
    Fetch the most recent logs for RENDER_SERVICE_ID from https://api.render.com/v1/logs.
    Returns a list of log entry dictionaries.
    """
    owner_id = get_owner_id()

    params = {
        "resource": RENDER_SERVICE_ID,
        "direction": "backward",
        "limit": limit
    }
    if owner_id:
        params["ownerId"] = owner_id

    try:
        data = render_http_get("logs", params)
    except urllib.error.HTTPError as e:
        # If ownerId was missing or rejected, try fallback
        if e.code in (400, 422) and not owner_id:
            print("[INFO] Retrying without ownerId...")
            params.pop("ownerId", None)
            data = render_http_get("logs", params)
        else:
            return []
    except Exception:
        return []

    # Standard Render response format: {"logs": [...], "hasMore": bool}
    # Or raw list of logs: [...]
    raw_logs = []
    if isinstance(data, list):
        raw_logs = data
    elif isinstance(data, dict):
        if "logs" in data and isinstance(data["logs"], list):
            raw_logs = data["logs"]
        elif "logLines" in data and isinstance(data["logLines"], list):
            raw_logs = data["logLines"]

    return raw_logs


def extract_otp(message: str) -> str:
    """
    Search a log message for an OTP or verification code matching predefined regex patterns.
    Returns the extracted code string or None.
    """
    for pattern in OTP_PATTERNS:
        match = pattern.search(message)
        if match:
            # Capture group 1 contains the digit sequence
            if match.groups():
                return match.group(1).strip()
            return match.group(0).strip()
    return None


def send_otp_email(otp_code: str, log_message: str, log_timestamp: str):
    """
    Send an email with the extracted OTP code to the recipient using Gmail SMTP SSL (port 465).
    """
    print(f"[+] Preparing to send OTP ({otp_code}) via email to {RECIPIENT_EMAIL}...")

    formatted_time = log_timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Construct EmailMessage
    msg = EmailMessage()
    msg["Subject"] = f"🔐 Your OTP / Verification Code: {otp_code}"
    msg["From"] = EMAIL_USER
    msg["To"] = RECIPIENT_EMAIL

    # Plaintext fallback body
    text_content = (
        f"Hello,\n\n"
        f"A new OTP / verification code was detected in your Render service logs.\n\n"
        f"OTP Code: {otp_code}\n"
        f"Timestamp: {formatted_time}\n"
        f"Service ID: {RENDER_SERVICE_ID}\n\n"
        f"Log Excerpt:\n"
        f"{log_message}\n\n"
        f"---\n"
        f"Sent automatically by Render OTP Agent.\n"
    )
    msg.set_content(text_content)

    # HTML body for clean, legible presentation
    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f4f6f8; margin: 0; padding: 20px; }}
    .card {{ max-width: 500px; margin: 20px auto; background: #ffffff; border-radius: 12px; padding: 32px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); border: 1px solid #e1e4e8; }}
    .header {{ text-align: center; margin-bottom: 24px; }}
    .title {{ font-size: 20px; color: #1a202c; font-weight: 700; margin: 0; }}
    .subtitle {{ font-size: 13px; color: #718096; margin-top: 6px; }}
    .otp-box {{ background: #f0fdf4; border: 2px dashed #22c55e; border-radius: 8px; padding: 18px; text-align: center; margin: 24px 0; }}
    .otp-code {{ font-size: 36px; font-weight: 800; letter-spacing: 6px; color: #15803d; font-family: 'Courier New', Courier, monospace; margin: 0; }}
    .details {{ background: #f8fafc; border-radius: 6px; padding: 14px; font-size: 13px; color: #475569; margin-top: 20px; }}
    .details dt {{ font-weight: 600; color: #334155; margin-top: 6px; }}
    .details dd {{ margin-left: 0; word-break: break-all; font-family: Consolas, monospace; }}
    .footer {{ text-align: center; font-size: 11px; color: #94a3b8; margin-top: 24px; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <h2 class="title">🔐 Verification Code Received</h2>
      <p class="subtitle">Dispatched from Render Service: <code>{RENDER_SERVICE_ID}</code></p>
    </div>
    <div class="otp-box">
      <div class="otp-code">{otp_code}</div>
    </div>
    <div class="details">
      <dt>Log Timestamp:</dt>
      <dd>{formatted_time}</dd>
      <dt>Raw Log Message:</dt>
      <dd>{log_message}</dd>
    </div>
    <div class="footer">
      This email was generated automatically by Render OTP Agent.
    </div>
  </div>
</body>
</html>"""
    msg.add_alternative(html_content, subtype="html")

    # Connect securely via SSL on port 465
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=30) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)

    print(f"[SUCCESS] OTP email successfully delivered to {RECIPIENT_EMAIL}!")


# ==========================================
# CORE PROCESSING PIPELINE
# ==========================================
def process_logs_once() -> int:
    """
    Fetch logs, inspect lines against last processed marker,
    extract unread OTPs, send email, and update last processed state.
    Returns count of new OTPs sent.
    """
    last_marker = read_last_processed()
    logs = fetch_render_logs(limit=100)

    if not logs:
        print("[*] No logs returned from Render.")
        return 0

    # Logs from Render with direction='backward' are ordered newest-first.
    # Reverse them to iterate chronologically (oldest -> newest).
    chronological_logs = list(reversed(logs))

    new_otps_count = 0
    newest_marker = last_marker

    for entry in chronological_logs:
        # Support both dict structure and plain string logs
        if isinstance(entry, dict):
            timestamp = entry.get("timestamp") or entry.get("id") or ""
            message = entry.get("message") or entry.get("text") or str(entry)
        else:
            timestamp = ""
            message = str(entry)

        # Skip logs that were already processed in earlier cycles
        if last_marker:
            # If timestamp is available and compares <= last_marker, skip
            if timestamp and timestamp <= last_marker:
                continue

        # Extract OTP from message line
        otp = extract_otp(message)
        if otp:
            print(f"[+] Detected new OTP in log: '{otp}'")
            print(f"    Message: {message.strip()}")
            try:
                send_otp_email(otp_code=otp, log_message=message.strip(), log_timestamp=timestamp)
                new_otps_count += 1
            except Exception as e:
                print(f"[ERROR] Failed to send email for OTP {otp}: {e}")
                # Don't update marker past this point if sending failed, so it retries next run
                break

        # Track the latest timestamp seen in this batch
        if timestamp and (not newest_marker or timestamp > newest_marker):
            newest_marker = timestamp

    # If first run and no marker was set yet, use the newest timestamp from the batch
    if newest_marker and newest_marker != last_marker:
        save_last_processed(newest_marker)

    return new_otps_count


# ==========================================
# CLI & MODES
# ==========================================
def main():
    parser = argparse.ArgumentParser(
        description="Render OTP Agent: Log parser and email dispatcher"
    )
    parser.add_argument(
        "--loop", "-l",
        action="store_true",
        help="Run continuously in a polling loop instead of a single check"
    )
    parser.add_argument(
        "--interval", "-i",
        type=int,
        default=POLL_INTERVAL,
        help=f"Polling interval in seconds for loop mode (default: {POLL_INTERVAL}s)"
    )
    parser.add_argument(
        "--test-email",
        action="store_true",
        help="Send a test verification email to confirm Gmail SMTP credentials"
    )
    args = parser.parse_args()

    # Validate configuration
    validate_config(require_email=True)

    # Test email mode
    if args.test_email:
        print("[*] Testing Gmail SMTP connection and email delivery...")
        test_otp = "123456"
        test_msg = "Render OTP Agent test run - verifying SMTP connection"
        send_otp_email(
            otp_code=test_otp,
            log_message=test_msg,
            log_timestamp=datetime.now(timezone.utc).isoformat()
        )
        print("[+] Test email completed successfully.")
        return

    # Continuous Polling Loop Mode
    if args.loop:
        print(f"=====================================================")
        print(f" Render OTP Agent started in Polling Loop Mode")
        print(f" Service ID : {RENDER_SERVICE_ID}")
        print(f" Recipient  : {RECIPIENT_EMAIL}")
        print(f" Interval   : {args.interval} seconds")
        print(f" State File : {STATE_FILE}")
        print(f" Press Ctrl+C to terminate.")
        print(f"=====================================================")

        try:
            while True:
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{now_str}] Polling Render logs...")
                sent = process_logs_once()
                if sent > 0:
                    print(f"[{now_str}] Dispatched {sent} new OTP(s).")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[*] Stopping Render OTP Agent. Goodbye!")
            sys.exit(0)

    # Single-Run Mode (for cron or Windows Task Scheduler)
    else:
        print(f"[*] Executing single poll for service {RENDER_SERVICE_ID}...")
        sent = process_logs_once()
        print(f"[+] Done. Dispatched {sent} new OTP(s).")


if __name__ == "__main__":
    main()
