#!/usr/bin/env python3
"""
VeloTest Local Webhook Tester for Render OTP Agent
===================================================
Simulates authentic Render Log Streams webhook POST requests containing
various VeloTest platform log formats to verify parsing, deduplication,
and email dispatch (via Brevo API or Gmail SMTP) on your local server.
"""

import os
import sys
import json
import random
import argparse
import urllib.request
import urllib.error
from datetime import datetime, timezone

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DEFAULT_SERVER_URL = "http://localhost:8000"
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()
DEFAULT_EMAIL = os.getenv("EMAIL_USER", "velotest2026@gmail.com").strip()


def check_health(base_url: str) -> bool:
    """Verify that the FastAPI server is running."""
    health_url = f"{base_url.rstrip('/')}/healthz"
    try:
        req = urllib.request.Request(health_url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as res:
            if res.getcode() == 200:
                print(f"[+] Server is reachable and healthy at {health_url}")
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
    format_type: str = "standard",
    token: str = None
) -> dict:
    """Send a simulated Render Log Stream payload to the webhook endpoint."""
    webhook_url = f"{base_url.rstrip('/')}/webhook/render-logs"
    now_iso = datetime.now(timezone.utc).isoformat()

    # Generate log message based on format_type
    if format_type == "velotest_bracket":
        msg = f"[VeloTest] Candidate {recipient_email} verification code generated: {otp_code}"
    elif format_type == "json":
        msg = json.dumps({"service": "velotest", "event": "otp_request", "email": recipient_email, "otp": otp_code})
    elif format_type == "colon":
        msg = f"OTP for {recipient_email}: {otp_code}"
    else:
        msg = f"OTP sent to {recipient_email}: {otp_code}"

    payload = {
        "logs": [
            {
                "id": "log-001",
                "timestamp": now_iso,
                "message": "VeloTest backend initialized session",
                "level": "info",
                "labels": {"serviceId": "srv-velotest"}
            },
            {
                "id": "log-002",
                "timestamp": now_iso,
                "message": msg,
                "level": "info",
                "labels": {"serviceId": "srv-velotest"}
            },
            {
                "id": "log-003",
                "timestamp": now_iso,
                "message": "Auth event recorded in VeloTest database",
                "level": "info",
                "labels": {"serviceId": "srv-velotest"}
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
        with urllib.request.urlopen(req, timeout=12) as response:
            status_code = response.getcode()
            body = response.read().decode("utf-8")
            return {"status_code": status_code, "body": json.loads(body), "sent_message": msg}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        return {"status_code": e.code, "error": error_body, "sent_message": msg}
    except Exception as e:
        return {"status_code": 0, "error": str(e), "sent_message": msg}


def main():
    parser = argparse.ArgumentParser(
        description="Simulate Render Log Streams for VeloTest OTP Agent"
    )
    parser.add_argument(
        "--url", "-u",
        default=DEFAULT_SERVER_URL,
        help=f"Base URL of running FastAPI app (default: {DEFAULT_SERVER_URL})"
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
        "--format", "-f",
        choices=["standard", "velotest_bracket", "json", "colon"],
        default="standard",
        help="Log line format to test (standard, velotest_bracket, json, colon)"
    )
    args = parser.parse_args()

    test_otp = args.otp if args.otp else str(random.randint(100000, 999999))
    target_email = args.email

    print("=================================================================")
    print(" 🚀 VeloTest Render Webhook Local Simulator")
    print("=================================================================")
    print(f" Target Webhook  : {args.url.rstrip('/')}/webhook/render-logs")
    print(f" Recipient Email : {target_email}")
    print(f" Test OTP Code   : {test_otp}")
    print(f" Format Selected : {args.format}")
    print("=================================================================\n")

    # 1. Health Check
    print("[1/3] Checking server health...")
    if not check_health(args.url):
        sys.exit(1)

    # 2. Webhook Delivery
    print("[2/3] Sending simulated VeloTest Render Log Stream payload...")
    res = send_simulated_webhook(
        base_url=args.url,
        recipient_email=target_email,
        otp_code=test_otp,
        format_type=args.format
    )

    if res.get("status_code") == 200:
        print(f"[SUCCESS] Webhook accepted by server (HTTP 200 OK)!")
        print(f"Log message simulated: \"{res.get('sent_message')}\"")
        print(f"Server Response:\n{json.dumps(res.get('body'), indent=2)}")
        print(f"\n📧 Check inbox for '{target_email}' to verify email arrival!")
    else:
        print(f"[ERROR] Request failed with HTTP {res.get('status_code')}:")
        print(res.get("error", "Unknown error"))
        sys.exit(1)

    # 3. Deduplication Check
    print("\n[3/3] Sending identical payload immediately to verify deduplication...")
    dedup_res = send_simulated_webhook(
        base_url=args.url,
        recipient_email=target_email,
        otp_code=test_otp,
        format_type=args.format
    )
    if dedup_res.get("status_code") == 200:
        body = dedup_res.get("body", {})
        otps_matched = body.get("otps_matched", 0)
        if otps_matched == 0:
            print("[SUCCESS] Deduplication verified! Duplicate OTP was safely ignored.")
        else:
            print(f"[WARN] Deduplication returned matched count: {otps_matched}")
    else:
        print(f"[WARN] Deduplication test request returned error: {dedup_res}")

    print("\n=================================================================")
    print(" Test finished.")
    print("=================================================================")


if __name__ == "__main__":
    main()
