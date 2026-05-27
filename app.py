import json
import base64
from os import environ as env
from urllib.parse import urlparse

from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import (
    LogoutOptions,
    StartInteractiveLoginOptions,
    StateData,
    TransactionData,
)
from auth0_server_python.store.abstract import AbstractDataStore
from dotenv import load_dotenv
from flask import Flask, after_this_request, redirect, render_template, request
from markupsafe import escape

load_dotenv()

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────
# Cookie Store — exactly as Auth0 recommends
# Stores session + transaction data in encrypted HttpOnly cookies
# This is safer than localStorage (XSS-proof) and sessionStorage
# ─────────────────────────────────────────────────────────────
class CookieStore(AbstractDataStore):
    def __init__(self, secret, cookie_name, max_age, model):
        super().__init__({"secret": secret})
        self.cookie_name = cookie_name
        self.max_age = max_age
        self.model = model

    async def set(self, identifier, state, **_):
        @after_this_request
        def apply(response):
            data = state.model_dump() if hasattr(state, "model_dump") else state
            response.set_cookie(
                self.cookie_name,
                self.encrypt(identifier, data),
                httponly=True,        # JS cannot access this cookie — XSS protection
                samesite="Lax",       # CSRF protection
                secure=not env.get("APP_BASE_URL", "").startswith("http://"),
                max_age=self.max_age,
            )
            return response

    async def get(self, identifier, options=None):
        try:
            encrypted = options["request"].cookies.get(self.cookie_name)
            return (
                self.model.model_validate(self.decrypt(identifier, encrypted))
                if encrypted
                else None
            )
        except Exception:
            app.logger.warning(
                "Failed to decrypt cookie %s", self.cookie_name, exc_info=True
            )
            return None

    async def delete(self, *_, **__):
        @after_this_request
        def apply(response):
            response.delete_cookie(self.cookie_name)
            return response


# ─────────────────────────────────────────────────────────────
# Auth0 / Okta CIC Client
# Uses Authorization Code Flow + PKCE under the hood
# ─────────────────────────────────────────────────────────────
def auth0():
    session_secret = env.get("AUTH0_SECRET")
    return ServerClient(
        domain=env.get("AUTH0_DOMAIN"),
        client_id=env.get("AUTH0_CLIENT_ID"),
        client_secret=env.get("AUTH0_CLIENT_SECRET"),
        redirect_uri=env.get("APP_BASE_URL") + "/callback",
        authorization_params={"scope": "openid profile email"},
        secret=session_secret,
        state_store=CookieStore(session_secret, "_a0_session", 259200, StateData),   # 3 days
        transaction_store=CookieStore(session_secret, "_a0_tx", 300, TransactionData),  # 5 min
    )


# ─────────────────────────────────────────────────────────────
# JWT Decoder — manual base64 decode (no verification)
# For display purposes only — shows user what's inside their token
# In production, always verify tokens server-side
# ─────────────────────────────────────────────────────────────
def decode_jwt_payload(token):
    try:
        # JWT = header.payload.signature — we want the payload (index 1)
        payload = token.split(".")[1]
        # Add padding if needed (base64 requires length % 4 == 0)
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────

@app.route("/")
async def home():
    user = await auth0().get_user({"request": request})
    if user:
        return redirect("/dashboard")
    return render_template("home.html")


@app.route("/login")
async def login():
    # Auth0 SDK handles: generating state param, PKCE verifier,
    # storing them in transaction cookie, building the authorization URL
    url = await auth0().start_interactive_login(
        options=StartInteractiveLoginOptions(
            authorization_params=dict(request.args),
        ),
        store_options={"request": request},
    )
    return redirect(url)


@app.route("/callback")
async def callback():
    try:
        # SDK validates: state param (CSRF check), PKCE verifier,
        # exchanges auth code for tokens, stores in session cookie
        await auth0().complete_interactive_login(
            url=request.url,
            store_options={"request": request},
        )
        return redirect("/dashboard")
    except Exception:
        app.logger.exception("Callback error")
        return render_template("home.html", error="Authentication failed. Please try again.")


@app.route("/dashboard")
async def dashboard():
    user = await auth0().get_user({"request": request})

    # Not logged in — send to home
    if not user:
        return redirect("/")

    # Extract tokens from user session for display
    access_token = user.get("access_token", "")
    id_token = user.get("id_token", "")

    # Decode JWT payloads for display
    access_token_claims = decode_jwt_payload(access_token) if access_token else {}
    id_token_claims = decode_jwt_payload(id_token) if id_token else {}

    return render_template(
        "dashboard.html",
        user=user,
        access_token=access_token,
        id_token=id_token,
        access_token_claims=access_token_claims,
        id_token_claims=id_token_claims,
        user_json=json.dumps(user, indent=2),
    )


@app.route("/logout")
async def logout():
    url = await auth0().logout(
        options=LogoutOptions(return_to=env.get("APP_BASE_URL")),
        store_options={"request": request},
    )
    return redirect(url)


if __name__ == "__main__":
    url = urlparse(env.get("APP_BASE_URL"))
    app.run(host=url.hostname, port=url.port or 5000, debug=True)