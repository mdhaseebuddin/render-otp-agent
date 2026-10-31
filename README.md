# ⚡ VeloTest Real-Time OTP Webhook Agent

A dedicated, high-performance **FastAPI** webhook log receiver and email dispatcher engineered to seamlessly accommodate the **VeloTest** platform on [Render](https://render.com) **with zero modifications required in VeloTest**.

Whenever VeloTest generates or logs an OTP verification code, Render's native **Log Streams (Log Drains)** immediately forward the log line to this service over HTTPS. The agent extracts both the **target candidate/user email** and the **OTP code**, then delivers a branded verification email via **Brevo REST API** or **Gmail SMTP SSL (port 465)**.

---

## 🏗️ Architecture: Zero Changes to VeloTest

```
┌───────────────────────────────────────────────┐
│              Existing VeloTest Platform       │
│  (Emits stdout log: "OTP sent to user: code") │
└───────────────────────┬───────────────────────┘
                        │
                        ▼ (Automatic Real-Time Push)
┌───────────────────────────────────────────────┐
│        Render HTTPS Log Stream / Drain        │
└───────────────────────┬───────────────────────┘
                        │
                        ▼ (POST /webhook/render-logs)
┌───────────────────────────────────────────────┐
│           VeloTest Render OTP Agent           │
│         (FastAPI running on Render Free)      │
│  - Inspects incoming JSON/NDJSON log batch    │
│  - Multi-pattern regex extracts email & OTP   │
│  - In-memory TTL deduplication prevents duplicates│
│  - Returns 200 OK to Render in < 10ms         │
└───────────────────────┬───────────────────────┘
                        │
                        ▼ (Non-blocking Background Task)
         ┌──────────────┴──────────────┐
         ▼                             ▼
   [Brevo REST API]            [Gmail SMTP SSL 465]
 (api.brevo.com/v3/smtp/email)    (smtp.gmail.com:465)
         │                             │
         └──────────────┬──────────────┘
                        │
                        ▼
         ┌─────────────────────────────┐
         │     Candidate's Inbox       │
         │   (Branded HTML OTP Card)   │
         └─────────────────────────────┘
```

---

## 🎯 Flexible Log Parsing Formats

The parser automatically recognizes all standard and custom formats produced by VeloTest:

| Log Style | Example Log Message | Extracted Email | Extracted OTP |
| :--- | :--- | :--- | :--- |
| **Standard** | `OTP sent to student@velotest.com: 593821` | `student@velotest.com` | `593821` |
| **Bracketed** | `[VeloTest] Candidate user@exam.org OTP generated: 849201` | `user@exam.org` | `849201` |
| **Reversed** | `Sent OTP 123456 to candidate@gmail.com` | `candidate@gmail.com` | `123456` |
| **Key-Value** | `VeloTest Auth | email: user@test.net | code: 771234` | `user@test.net` |
| **JSON Log** | `{"service": "velotest", "email": "alice@velotest.io", "otp": "993821"}` | `alice@velotest.io` | `993821` |
| **Colon Style** | `OTP for student@velotest.com: 654321` | `student@velotest.com` | `654321` |

*Need a unique pattern? Set `OTP_CUSTOM_REGEX` in `.env` to override at any time.*

---

## ⚙️ Environment Configuration (`.env`)

Configure either **Brevo API** (recommended for production volume) or **Gmail SMTP**:

```env
# 1. Provider Selection: 'auto', 'brevo', or 'gmail'
# 'auto' prioritizes Brevo if BREVO_API_KEY is present, else falls back to Gmail SMTP
EMAIL_PROVIDER=auto

# 2. Option A: Brevo (Sendinblue) API Credentials
BREVO_API_KEY=xkeysib-your_brevo_api_key_here
BREVO_SENDER_EMAIL=no-reply@yourdomain.com
BREVO_SENDER_NAME=VeloTest Verification

# 3. Option B: Gmail SMTP Credentials
EMAIL_USER=velotest2026@gmail.com
EMAIL_PASS=your_16_char_gmail_app_password
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465

# 4. Webhook Security (Optional)
# If you set a token in Render's Log Stream configuration, place it here:
WEBHOOK_SECRET=

# 5. App Settings
APP_NAME=VeloTest Verification
DEDUP_CACHE_TTL=300
PORT=8000
```

---

## 🧪 Local Verification & Testing

Before deploying, you can test everything on your machine:

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Parser Unit Tests
Verifies all VeloTest formats against regex & deduplication:
```bash
python test_webhook.py
```

### 3. Start Local FastAPI Webhook Server
```bash
uvicorn app:app --reload --port 8000
```

### 4. Run the Local Simulator (Sends real test email)
In another terminal, simulate Render pushing a VeloTest log:
```bash
python test_local.py --email your_email@gmail.com --format standard
```
Other test formats available:
```bash
python test_local.py --email your_email@gmail.com --format velotest_bracket
python test_local.py --email your_email@gmail.com --format json
```
Check your inbox to verify the arrival of the branded VeloTest verification card.

---

## 🚀 Mapping Render's Log Streams to VeloTest

Once you deploy this agent as a free web service on Render, wire it to your existing VeloTest deployment in under 60 seconds:

### Step 1: Deploy `render-otp-agent` on Render
1. Push this repository to GitHub/GitLab.
2. In [Render Dashboard](https://dashboard.render.com), click **New +** $\rightarrow$ **Web Service**.
3. Select this repository:
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app:app --host 0.0.0.0 --port $PORT`
   - **Plan**: **Free**
   - **Health Check Path**: `/healthz`
4. Add your `.env` variables (`BREVO_API_KEY` or `EMAIL_USER` / `EMAIL_PASS`).
5. Copy your deployed service URL (e.g., `https://velotest-otp-agent.onrender.com`).

### Step 2: Configure Render Log Stream for VeloTest
1. In the Render Dashboard, open your **VeloTest** service (or go to **Workspace Settings** $\rightarrow$ **Integrations** $\rightarrow$ **Observability**).
2. Scroll to the **Log Streams** section and click **Add Log Stream** (or **Edit**):
   - **Destination**: `HTTPS`
   - **Log Endpoint**: 
     ```
     https://velotest-otp-agent.onrender.com/webhook/render-logs
     ```
   - **Token**: *(Optional)* Enter a secret token matching `WEBHOOK_SECRET` in `.env`.
3. Click **Save Changes**.

---

## 💡 Keeping Free Render Web Services Awake

Render free web services enter sleep mode after 15 minutes of inactivity:
- Whenever candidates interact with VeloTest, Render streams the logs to this endpoint, keeping it active.
- To ensure zero cold-start delay during off-peak hours, set up a free 10-minute ping monitor (via [UptimeRobot](https://uptimerobot.com) or [Cron-job.org](https://cron-job.org)) targeting:
  `https://velotest-otp-agent.onrender.com/healthz`
