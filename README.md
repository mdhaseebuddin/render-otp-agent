# ⚡ VeloTest Real-Time OTP Webhook Agent

A dedicated, high-performance **FastAPI** webhook log receiver and email dispatcher engineered for **VeloTest** on [Render](https://render.com) **with zero modifications required in VeloTest**.

Whenever VeloTest generates or logs an OTP verification code, Render's native **Log Streams (Log Drains)** immediately forward the log line to this service over HTTPS. The agent extracts both the **target candidate/user email** and the **OTP code**, then delivers a branded verification email over **Brevo HTTPS REST API (Port 443)**.

---

## 🚫 Why Pure HTTPS REST API (Port 443)?

> [!IMPORTANT]
> **Render blocks raw outbound SMTP ports (465, 587, 25)** on all Free Tier instances, producing `[Errno 101] Network is unreachable` when attempting to connect to `smtp.gmail.com`.
>
> To bypass this restriction completely, this service transmits all emails via **Brevo's v3 REST API (`POST https://api.brevo.com/v3/smtp/email`) over standard HTTPS (Port 443)**. Outbound HTTPS traffic is 100% permitted and uninterrupted on Render's Free Tier.

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
   [Brevo v3 REST API]        [Port 443 HTTPS Request]
 (https://api.brevo.com/v3/smtp/email)
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

---

## ⚙️ Environment Configuration (`.env`)

Configure your Brevo API key and sender email in `.env`:

```env
# 1. Brevo HTTPS REST API Credentials (Port 443)
# Get your API key from: https://app.brevo.com/settings/keys/api
BREVO_API_KEY=xkeysib-your_brevo_api_key_here
BREVO_API_KEY_FALLBACK=

# Sender Details (Must be a verified sender in your Brevo account)
SENDER_EMAIL=mdhaseebuddin24@gmail.com
SENDER_NAME=VeloTest Security

# 2. Webhook Security (Optional)
# Matches the Token set in Render Log Streams configuration (leave empty for none)
WEBHOOK_SECRET=

# 3. App Settings
APP_NAME=VeloTest Security
DEDUP_CACHE_TTL=300
PORT=8000
```

---

## 🧪 Local Verification & Testing

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Parser Unit Tests
```bash
python test_webhook.py
```

### 3. Start Local FastAPI Webhook Server
```bash
uvicorn app:app --reload --port 8000
```

### 4. Direct Test Dispatch via Brevo API
You can test sending a verification email directly to your inbox:
```bash
# Using curl:
curl -X POST "http://localhost:8000/test-send?email=your_email@gmail.com&otp=593821"
```
Or run the simulated webhook test:
```bash
python test_local.py --email your_email@gmail.com
```

---

## 🚀 Mapping Render's Log Streams to VeloTest

### Step 1: Deploy on Render
1. Push this repository to GitHub/GitLab.
2. In [Render Dashboard](https://dashboard.render.com), click **New +** $\rightarrow$ **Web Service**.
3. Select this repository:
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app:app --host 0.0.0.0 --port $PORT`
   - **Plan**: **Free**
   - **Health Check Path**: `/healthz`
4. Add environment variables:
   - `BREVO_API_KEY`: Your Brevo API key (`xkeysib-...`)
   - `SENDER_EMAIL`: `mdhaseebuddin24@gmail.com` (or your verified Brevo sender)
5. Copy your deployed service URL (e.g., `https://velotest-otp-agent.onrender.com`).

### Step 2: Configure Render Log Stream for VeloTest
1. In the Render Dashboard, open your **VeloTest** service $\rightarrow$ **Settings** $\rightarrow$ **Log Streams**.
2. Click **Add Log Stream**:
   - **Destination**: `HTTPS`
   - **Log Endpoint**: 
     ```
     https://velotest-otp-agent.onrender.com/webhook/render-logs
     ```
   - **Token**: *(Optional)* Enter a token matching `WEBHOOK_SECRET` in `.env`.
3. Click **Save Changes**.

Whenever VeloTest logs an OTP, Render streams it to this webhook, and Brevo immediately emails the user over HTTPS port 443 with sub-second latency!
