@echo off
REM Render OTP Agent Windows Launcher
REM Runs in continuous polling loop mode by default

echo Starting Render OTP Agent in continuous loop mode...
python render_otp_agent.py --loop
pause

