# ⚡ VeloTest Real-Time OTP Webhook Agent (Gmail REST API)

A dedicated, high-performance **FastAPI** webhook log receiver and email dispatcher engineered for **VeloTest** on [Render](https://render.com) **with zero modifications required in VeloTest**.

Whenever VeloTest outputs an OTP log line, Render's native **Log Streams (Log Drains)** immediately forward the log line to this service over HTTPS. The agent extracts both the **target candidate/user email** and the **OTP code**, then delivers a branded verification email over the **official Google Gmail REST API (`https://gmail.googleapis.com`) over HTTPS (Port 443)** using OAuth2 refresh tokens.

---

## 🚫 Why Official Gmail REST API over HTTPS (Port 443)?

> [!IMPORTANT]
> **Render blocks raw outbound SMTP ports (465, 587, 25)** on all Free Tier instances, producing `[Errno 101] Network is unreachable` when attempting to connect to `smtp.gmail.com`.
>
> To bypass this restriction completely, this service transmits all emails via **Google's official Gmail REST API (`POST https://gmail.googleapis.com/gmail/v1/users/me/messages/send`) over standard HTTPS (Port 443)** using OAuth2 access token refresh. Outbound HTTPS traffic is 100% permitted and uninterrupted on Render's Free Tier.

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
│  - Refreshes short-lived Google OAuth2 token  │
│  - Base64url encodes RFC 2822 email message   │
│  - Dispatches via Gmail REST API (Port 443)   │
│  - Returns 200 OK: channel: gmail_rest_api    │
└───────────────────────┬───────────────────────┘
                        │
                        ▼ (Port 443 HTTPS Request)
 ┌─────────────────────────────────────────────┐
 │       Google Gmail REST API (v1)            │
 │ (https://gmail.googleapis.com/.../send)     │
 └──────────────────────┬──────────────────────┘
                        │
                        ▼
 ┌─────────────────────────────────────────────┐
 │           Candidate's Inbox                 │
 │        (Branded HTML OTP Card)              │
 └─────────────────────────────────────────────┘
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

Configure your Google OAuth2 credentials in `.env`:

```env
# 1. Google OAuth2 Credentials
# Obtained from Google Cloud Console (APIs & Services -> Credentials)
GMAIL_CLIENT_ID=your_client_id_here.apps.googleusercontent.com
GMAIL_CLIENT_SECRET=GOCSPX-your_client_secret_here
GMAIL_REFRESH_TOKEN=1//your_refresh_token_here

# 2. Sender Email
SENDER_EMAIL=velotest2026@gmail.com

# 3. Webhook Security (Optional)
# Matches the Token set in Render Log Streams configuration (leave empty for none)
WEBHOOK_SECRET=

# 4. App Settings
APP_NAME=VeloTest
DEDUP_CACHE_TTL=300
PORT=8000
```

---

## 🔑 How to Obtain Google OAuth2 Credentials

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create or select a project.
3. Enable the **Gmail API** under **APIs & Services** $\rightarrow$ **Library**.
4. In **OAuth consent screen**, set user type to **External** and add your Gmail account (`velotest2026@gmail.com`) as a test user.
5. In **Credentials**, click **Create Credentials** $\rightarrow$ **OAuth client ID**:
   - Application type: **Web application** (or Desktop app)
   - Authorized redirect URIs: `https://developers.google.com/oauthplayground`
   - Copy your `GMAIL_CLIENT_ID` and `GMAIL_CLIENT_SECRET`.
6. Open [OAuth 2.0 Playground](https://developers.google.com/oauthplayground/):
   - Click the gear icon (top right) $\rightarrow$ check **Use your own OAuth credentials** $\rightarrow$ paste Client ID & Client Secret.
   - Under Step 1, find **Gmail API v1** and select `https://www.googleapis.com/auth/gmail.send`.
   - Click **Authorize APIs** and log in with your Gmail account (`velotest2026@gmail.com`).
   - In Step 2, click **Exchange authorization code for tokens**.
   - Copy the generated **Refresh token** into `GMAIL_REFRESH_TOKEN`.

---

## 🧪 Local Verification & Testing

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Verify Python Compilation
```bash
python -m py_compile main.py app.py
```

### 3. Run Parser Unit Tests
```bash
python test_webhook.py
```

### 4. Start Local FastAPI Webhook Server
```bash
uvicorn app:app --reload --port 8000
```

### 5. Direct Test Dispatch via Gmail REST API
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
   - `GMAIL_CLIENT_ID`: Your Google OAuth2 Client ID
   - `GMAIL_CLIENT_SECRET`: Your Google OAuth2 Client Secret
   - `GMAIL_REFRESH_TOKEN`: Your Google OAuth2 Refresh Token
   - `SENDER_EMAIL`: `velotest2026@gmail.com`
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

Whenever VeloTest logs an OTP, Render streams it to this webhook, and Gmail REST API immediately emails the user over HTTPS port 443 with sub-second latency!
