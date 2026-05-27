# 🔐 Okta Auth Demo

A minimal Flask web application demonstrating enterprise-grade authentication  
using **Okta's Customer Identity Cloud (Auth0)**. Built to understand and  
visualize the full OAuth2 + OIDC authentication flow in practice.

---

## What This Demonstrates

| Concept | Implementation |
| --- | --- |
| **Authorization Code Flow + PKCE** | Auth0 Python SDK handles code exchange and PKCE verifier |
| **OIDC (OpenID Connect)** | ID Token issued alongside Access Token |
| **JWT Structure** | Live decoding of token claims in the dashboard |
| **Secure Session Storage** | Encrypted HttpOnly cookies (XSS-proof) |
| **CSRF Protection** | State parameter validation + SameSite cookie policy |
| **ID Token vs Access Token** | Side-by-side claim comparison in the UI |

---

## How It Works

```text
User clicks "Login with Okta"
→ App generates PKCE code verifier + state param
→ User redirected to Okta's hosted login page
→ User authenticates (username/password or social login)
→ Okta redirects back to /callback with authorization code
→ App exchanges code for tokens (Access Token + ID Token)
→ Tokens stored in encrypted HttpOnly cookie session
→ Dashboard displays decoded JWT claims
```

---

## Tech Stack

- **Backend:** Python / Flask
- **Auth:** Auth0 Python SDK (`auth0-server-python`)
- **Session Storage:** Encrypted HttpOnly cookies via `AbstractDataStore`
- **Templating:** Jinja2
- **Identity Provider:** Okta Customer Identity Cloud (Auth0)

---

## Project Structure

```text
okta-demo/
├── app.py                 # Flask app + Auth0 config + routes
├── .env                   # Environment variables (not committed)
├── .env.example           # Template for environment variables
├── requirements.txt       # Python dependencies
└── templates/
    ├── home.html          # Landing page (login/signup)
    └── dashboard.html     # Post-login view with token details
```

---

## Getting Started

### Prerequisites

- Python 3.8+
- An [Okta Developer Account](https://developer.okta.com) (free)

### 1. Clone the repo

```bash
git clone https://github.com/your-username/okta-auth-demo.git
cd okta-auth-demo
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Okta

In your Okta/Auth0 Admin Console:

- Create a new Web Application
- Set Callback URL to `http://localhost:5000/callback`
- Set Logout URL to `http://localhost:5000`
- Copy your Client ID, Client Secret, and Domain

### 4. Set up environment variables

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

```env
AUTH0_DOMAIN=dev-xxxxxxxx.okta.com
AUTH0_CLIENT_ID=your_client_id_here
AUTH0_CLIENT_SECRET=your_client_secret_here
AUTH0_SECRET=any_random_32_char_string_here
APP_BASE_URL=http://localhost:5000
```

### 5. Run the app

```bash
python app.py
```

Open your browser at `http://localhost:5000`
