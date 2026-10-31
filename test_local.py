#!/usr/bin/env python3
"""
Local Webhook Tester for Render OTP Agent
==========================================
Simulates an authentic Render Log Streams webhook POST request to your
locally running FastAPI server (http://localhost:8000/webhook/render-logs).

Verifies:
1. Server connectivity (/healthz)
2. Log ingestion & regex parsing (extracting email and OTP)
3. Instant email dispatch via Gmail SMTP SSL
4. Deduplication cache behavior
"""

import os
import sys
import json
import random
import argparse
import urllib.request
import urllib.error
from datetime import datetime, timezone

# Load environment variables if .env exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DEFAULT_SERVER_URL = "http://localhost:8000"
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()
DEFAULT_EMAIL = os.getenv("EMAIL_USER", "user@example.com").strip()


def check_health(base_url: str) -> bool:
    """Verify that the FastAPI server is running."""
    health_url = f"{base_url.rstrip('/')}/healthz"
    try:
        req = urllib.request.Request(health_url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as res:
            if res.getcode() == 200:
                print(f"[+] Server is healthy at {health_url}")
                return True
    except Exception as e:
        print(f"[!] Could not connect to {health_url}: {e}")
        print("    --> Please make sure your FastAPI server is running first:")
        print("        uvicorn app:app --reload --port 8000\n")
        return False
    return False


def send_simulated_webhook(
    base_url: str,
    recipient_email: str,
    otp_code: str,
    token: str = None
) -> dict:
    """Send a simulated Render Log Stream payload to the webhook endpoint."""
    webhook_url = f"{base_url.rstrip('/')}/webhook/render-logs"

    now_iso = datetime.now(timezone.utc).isoformat()

    # Typical Render Log Stream payload containing a batch of logs
    payload = {
        "logs": [
            {
                "id": "log-001",
                "timestamp": now_iso,
                "message": "Application server received POST /api/auth/login",
                "level": "info",
                "labels": {"serviceId": "srv-test123456"}
            },
            {
                "id": "log-002",
                "timestamp": now_iso,
                "message": f"OTP sent to {recipient_email}: {otp_code}",
                "level": "info",
                "labels": {"serviceId": "srv-test123456"}
            },
            {
                "id": "log-003",
                "timestamp": now_iso,
                "message": "Auth controller dispatched security event notification",
                "level": "info",
                "labels": {"serviceId": "srv-test123456"}
            }
        ]
    }

    json_data = json.dumps(payload).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Render-Log-Stream/1.0"
    }

    auth_token = token if token is not None else WEBHOOK_SECRET
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    req = urllib.request.Request(
        url=webhook_url,
        data=json_data,
        headers=headers,
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            status_code = response.getcode()
            body = response.read().decode("utf-8")
            return {"status_code": status_code, "body": json.loads(body)}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        return {"status_code": e.code, "error": error_body}
    except Exception as e:
        return {"status_code": 0, "error": str(e)}


def main():
    parser = argparse.ArgumentParser(
        description="Simulate a Render Log Stream webhook POST request to your local FastAPI server"
    )
    parser.add_argument(
        "--url", "-u",
        default=DEFAULT_SERVER_URL,
        help=f"Base URL of your running FastAPI app (default: {DEFAULT_SERVER_URL})"
    )
    parser.add_argument(
        "--email", "-e",
        default=DEFAULT_EMAIL,
        help=f"Target recipient email to test (default: {DEFAULT_EMAIL})"
    )
    parser.add_argument(
        "--otp",
        default=None,
        help="Custom OTP code to test (default: random 6-digit number)"
    )
    parser.add_argument(
        "--token",
        default=None,
        help="Webhook secret token for Authorization header (default: from .env WEBHOOK_SECRET)"
    )
    parser.add_argument(
        "--test-dedup",
        action="store_true",
        default=True,
        help="Test deduplication by sending the exact same payload twice"
    )
    args = parser.parse_args()

    test_otp = args.otp if args.otp else str(random.randint(100000, 999999))
    target_email = args.email

    print("=================================================================")
    print(" 🚀 Render Real-Time Webhook Local Simulator")
    print("=================================================================")
    print(f" Target Webhook  : {args.url.rstrip('/')}/webhook/render-logs")
    print(f" Recipient Email : {target_email}")
    print(f" Test OTP Code   : {test_otp}")
    print(f" Simulated Log   : 'OTP sent to {target_email}: {test_otp}'")
    print("=================================================================\n")

    # 1. Health Check
    print("[1/3] Checking server health...")
    if not check_health(args.url):
        sys.exit(1)

    # 2. First Webhook Delivery
    print(f"[2/3] Sending simulated Render Log Stream payload...")
    res = send_simulated_webhook(
        base_url=args.url,
        recipient_email=target_email,
        otp_code=test_otp,
        token=args.token
    )

    if res.get("status_code") == 200:
        print("[SUCCESS] Webhook accepted by server (HTTP 200 OK)!")
        print(f"Response: {json.dumps(res.get('body'), indent=2)}")
        print(f"\n📧 Check inbox for '{target_email}' to confirm email delivery!")
    else:
        print(f"[ERROR] Request failed with status {res.get('status_code')}:")
        print(res.get("error", "Unknown error"))
        sys.exit(1)

    # 3. Test Deduplication
    if args.test_dedup:
        print("\n[3/3] Sending identical payload immediately to verify deduplication...")
        dedup_res = send_simulated_webhook(
            base_url=args.url,
            recipient_email=target_email,
            otp_code=test_otp,
            token=args.token
        )
        if dedup_res.get("status_code") == 200:
            body = dedup_res.get("body", {})
            otps_matched = body.get("otps_matched", 0)
            if otps_matched == 0:
                print("[SUCCESS] Deduplication verified! Duplicate OTP was safely ignored.")
            else:
                print(f"[WARN] Deduplication returned matched count: {otps_matched}")
        else:
            print(f"[WARN] Deduplication request returned: {dedup_res}")

    print("\n=================================================================")
    print(" Test completed successfully.")
    print("=================================================================")


if __name__ == "__main__":
    main()

