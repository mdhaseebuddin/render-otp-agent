import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from fastapi import FastAPI, HTTPException, Request

app = FastAPI(title="VeloTest OTP Dispatcher")

EMAIL_USER = os.getenv("EMAIL_USER") or os.getenv("SENDER_EMAIL")
EMAIL_PASS = os.getenv("EMAIL_PASS")


def send_otp_via_smtp(to_email: str, otp_code: str):
  if not EMAIL_USER or not EMAIL_PASS:
    raise ValueError(
        "Missing EMAIL_USER or EMAIL_PASS environment variables on Render."
    )

  msg = MIMEMultipart()
  msg["From"] = EMAIL_USER
  msg["To"] = to_email
  msg["Subject"] = "Your VeloTest Verification Code"

  body = f"""Hello,

Your verification code is: {otp_code}

This code will expire in 10 minutes. If you did not request this, please ignore this email.

— VeloTest Security Team
"""
  msg.attach(MIMEText(body, "plain"))

  # Connect to Gmail SMTP SSL on port 465
  with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
    server.login(EMAIL_USER, EMAIL_PASS)
    server.sendmail(EMAIL_USER, to_email, msg.as_string())


@app.get("/")
def health_check():
  return {"status": "ok", "service": "VeloTest OTP Agent"}


@app.post("/webhook/render-logs")
async def handle_render_log(request: Request):
  payload = await request.json()
  # If Render log stream payload passes data or direct dispatch
  log_text = str(payload)

  # Check if dispatch contains email and OTP
  if "mdhaseebuddin24@gmail.com" in log_text or "OTP:" in log_text:
    import re

    otp_match = re.search(r"OTP:\s*(\d{4,6})", log_text)
    email_match = re.search(
        r"[\w\.-]+@[\w\.-]+\.\w+",
        log_text.split("dispatcher for")[-1]
        if "dispatcher for" in log_text
        else log_text,
    )

    recipient = (
        email_match.group(0)
        if email_match
        else "mdhaseebuddin24@gmail.com"
    )
    otp = otp_match.group(1) if otp_match else "123456"

    try:
      send_otp_via_smtp(recipient, otp)
      return {
          "status": "success",
          "message": f"OTP {otp} sent to {recipient}",
      }
    except Exception as e:
      raise HTTPException(status_code=500, detail=str(e))

  return {"status": "ignored"}


@app.post("/send-otp")
async def send_direct(data: dict):
  to_email = data.get("email")
  otp_code = data.get("otp")

  if not to_email or not otp_code:
    raise HTTPException(status_code=400, detail="Missing email or otp")

  try:
    send_otp_via_smtp(to_email, otp_code)
    return {
        "status": "success",
        "message": f"OTP {otp_code} dispatched to {to_email}",
    }
  except Exception as e:
    raise HTTPException(status_code=500, detail=str(e))