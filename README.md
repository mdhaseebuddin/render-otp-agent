# ⚡ Render Real-Time OTP Webhook Log Receiver

A high-performance, asynchronous web service built with **FastAPI** that receives real-time log streams directly from **Render Log Streams (Log Drains)** via HTTPS Webhook.

It inspects incoming log payloads in sub-seconds, extracts the **dynamic recipient user email** and **OTP verification code**, and immediately dispatches an email via **Gmail SMTP SSL (port 465)**.

---

## 🌟 Why Webhook Instead of Polling?

| Metric | Old Polling Script | New Webhook Log Receiver |
| :--- | :--- | :--- |
| **Latency** | 15 – 60 seconds delay | **< 100 milliseconds (Instantaneous)** |
| **Concurrency** | Single sequential loop | **Hundreds of concurrent users** |
| **Target Email** | Fixed static admin email | **Dynamic user email extracted per log** |
| **Rate Limits** | Hits Render REST API rate limits | **Zero polling — Render pushes to you** |
| **Hosting** | Requires your PC running or cron | **Runs 24/7 free on Render** |

---

## 📁 Repository Structure

```
otpsender_email/
├── app.py              # Main FastAPI Webhook & SMTP Dispatcher
├── requirements.txt    # Production dependencies (FastAPI, Uvicorn, python-dotenv)
├── Procfile            # Render web server start command
├── render.yaml         # One-click Render Blueprint specification
├── test_webhook.py     # Local verification test suite
├── .env.example        # Environment variable template
└── README.md           # Documentation & setup instructions
```

---

## 📋 Prerequisites

1. **Gmail Account with 2FA**:
   - Turn on **2-Step Verification** on your Google Account.
   - Go to [Google App Passwords](https://myaccount.google.com/apppasswords).
   - Generate a 16-character password named `RenderOTPWebhook`.
2. **Render Account**: Free tier account at [render.com](https://render.com).

---

## 🛠️ Step 1: Configure Environment Variables

Create or edit `.env` based on `.env.example`:

```env
# Gmail SMTP Credentials
EMAIL_USER=your_sender_gmail@gmail.com
EMAIL_PASS=abcd efgh ijkl mnop

# Optional: Webhook Secret Token (matches Token set in Render Log Streams)
WEBHOOK_SECRET=your_optional_secret_token

# Optional Settings
APP_NAME=Render OTP Dispatcher
DEDUP_CACHE_TTL=300
PORT=8000
```

---

## 🧪 Step 2: Test Locally

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Test Suite
Verify that the regex parser and deduplication logic extract target emails and OTP codes accurately:
```bash
python test_webhook.py
```

### 3. Run the Web Server Locally
```bash
python -m uvicorn app:app --reload --port 8000
```
Visit `http://localhost:8000/docs` in your browser to view the interactive OpenAPI/Swagger documentation.

---

## 🚀 Step 3: Deploy Free 24/7 on Render

### Method A: Connect Your GitHub/GitLab Repository
1. Push this repository to GitHub/GitLab (when you are ready).
2. Go to the [Render Dashboard](https://dashboard.render.com).
3. Click **New +** $\rightarrow$ **Web Service**.
4. Select your repository.
5. Configure the service:
   - **Name**: `render-otp-webhook`
   - **Environment**: `Python 3`
   - **Region**: Oregon (or your preferred region)
   - **Branch**: `main`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app:app --host 0.0.0.0 --port $PORT`
   - **Instance Type**: **Free**
   - **Health Check Path**: `/healthz`
6. Under **Environment Variables**, add:
   - `EMAIL_USER`: Your Gmail address
   - `EMAIL_PASS`: Your 16-character Gmail App Password
   - `WEBHOOK_SECRET`: (Optional) Your secret security token
7. Click **Create Web Service**.

Once deployed, Render gives you a public URL such as:
`https://render-otp-webhook-xxxx.onrender.com`

---

## 🔗 Step 4: Wire Render Log Streams to Your Webhook

Now point your main Render application's logs to this webhook:

1. In the [Render Dashboard](https://dashboard.render.com), go to **Integrations** $\rightarrow$ **Observability** (or click your main application service $\rightarrow$ **Settings** $\rightarrow$ **Log Streams**).
2. Locate **Log Streams** $\rightarrow$ Click **Add Log Stream** (or **Edit** default destination).
3. Set the fields:
   - **Log Endpoint**: 
     ```
     https://your-webhook-service.onrender.com/webhook/render-logs
     ```
   - **Token**: If you set `WEBHOOK_SECRET` in `.env`, paste that exact string here. Otherwise leave empty.
4. Click **Save Changes**.

---

## 🔍 How Log Parsing Works

Whenever your backend logs an OTP message, such as:
```python
print(f"OTP sent to {user_email}: {otp_code}")
```
or
```python
logger.info(f"Verification code for {user_email} is {otp_code}")
```

Render immediately streams this log line over HTTPS POST to `/webhook/render-logs`.

The webhook:
1. Validates the authorization token (if configured).
2. Extracts `user@example.com` and `593821` using multi-pattern regex.
3. Checks the in-memory cache to guarantee no duplicate emails are sent if Render retries a packet.
4. Responds `200 OK` in $< 10\text{ms}$ so Render never experiences webhook timeouts.
5. In the background task, establishes a secure SSL connection to `smtp.gmail.com:465` and delivers a clean HTML card with the OTP directly to the user!

---

## 💡 Keeping Free Render Web Services Awake

Render's free web services sleep after 15 minutes of inactivity:
- Because Render Log Streams continuously pushes log activity to this endpoint whenever your main app receives traffic, it naturally stays awake!
- To guarantee 100% 24/7 instant response even during off-peak hours, you can add a free ping monitor (e.g. [UptimeRobot](https://uptimerobot.com) or [Cron-job.org](https://cron-job.org)) that pings `https://your-webhook-service.onrender.com/healthz` every 10 minutes.
