#!/usr/bin/env python3
"""
Demo application that authenticates users via Keycloak OIDC.
"""
import os
import json
from functools import wraps
from flask import Flask, redirect, url_for, session, request, render_template_string
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Fix for running behind a reverse proxy (OpenShift route)
# This ensures url_for generates https:// URLs
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# OIDC Configuration from environment
KEYCLOAK_URL = os.environ.get('KEYCLOAK_URL', 'https://keycloak-keycloak.apps.rosa.rosa-69t6c.hyq5.p3.openshiftapps.com')
KEYCLOAK_REALM = os.environ.get('KEYCLOAK_REALM', 'demo')
CLIENT_ID = os.environ.get('CLIENT_ID', 'demo-app')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET', 'demo-app-secret-12345')

# OAuth setup
oauth = OAuth(app)
oauth.register(
    name='keycloak',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=f'{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# HTML Templates
BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - OIDC Demo</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #e4e4e4;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        .card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 40px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            margin-bottom: 20px;
        }
        h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            background: linear-gradient(90deg, #00d4ff, #7b2ff7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        h2 { color: #00d4ff; margin-bottom: 15px; }
        p { line-height: 1.6; margin-bottom: 15px; color: #b4b4b4; }
        .btn {
            display: inline-block;
            padding: 12px 30px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            margin: 5px;
        }
        .btn-primary {
            background: linear-gradient(90deg, #00d4ff, #7b2ff7);
            color: white;
        }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(0, 212, 255, 0.3); }
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        .btn-danger:hover { background: #c82333; }
        .user-info {
            background: rgba(0, 212, 255, 0.1);
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
        }
        .user-info dt { color: #00d4ff; font-weight: 600; margin-top: 10px; }
        .user-info dd { color: #e4e4e4; margin-left: 0; padding: 5px 0; }
        .token-box {
            background: #0d1117;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
            overflow-x: auto;
            font-family: monospace;
            font-size: 12px;
            color: #7ee787;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            margin: 2px;
        }
        .badge-success { background: rgba(0, 200, 83, 0.2); color: #00c853; }
        .header-info {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        .status { font-size: 0.9rem; }
        .status.authenticated { color: #00c853; }
        .status.unauthenticated { color: #ff5252; }
    </style>
</head>
<body>
    <div class="container">
        {{ content | safe }}
    </div>
</body>
</html>
'''

HOME_CONTENT = '''
<div class="card">
    <div class="header-info">
        <div>
            <h1>🔐 OIDC Demo App</h1>
            <p>Authenticate with Keycloak Identity Provider</p>
        </div>
        <div class="status unauthenticated">● Not Authenticated</div>
    </div>
</div>

<div class="card">
    <h2>Welcome!</h2>
    <p>This application demonstrates OpenID Connect (OIDC) authentication using Keycloak as the Identity Provider.</p>
    <p>Click the button below to sign in with your Keycloak credentials.</p>
    <a href="/login" class="btn btn-primary">Sign In with Keycloak</a>
</div>

<div class="card">
    <h2>How it works</h2>
    <p>1. You click "Sign In" and get redirected to Keycloak</p>
    <p>2. Keycloak authenticates you (username/password)</p>
    <p>3. Keycloak redirects back with an authorization code</p>
    <p>4. This app exchanges the code for tokens (ID token, access token)</p>
    <p>5. The ID token contains your identity claims</p>
</div>
'''

PROFILE_CONTENT = '''
<div class="card">
    <div class="header-info">
        <div>
            <h1>🔐 OIDC Demo App</h1>
            <p>Authenticated Session</p>
        </div>
        <div class="status authenticated">● Authenticated</div>
    </div>
</div>

<div class="card">
    <h2>👤 User Profile</h2>
    <div class="user-info">
        <dl>
            <dt>Username</dt>
            <dd>{{ user.preferred_username or user.sub }}</dd>
            <dt>Email</dt>
            <dd>{{ user.email or 'Not provided' }}</dd>
            <dt>Full Name</dt>
            <dd>{{ user.name or (user.given_name + ' ' + user.family_name) if user.given_name else 'Not provided' }}</dd>
            <dt>Subject (sub)</dt>
            <dd>{{ user.sub }}</dd>
            <dt>Email Verified</dt>
            <dd>{{ 'Yes' if user.email_verified else 'No' }}</dd>
        </dl>
    </div>
    <a href="/logout" class="btn btn-danger">Sign Out</a>
    <a href="/" class="btn btn-primary">Home</a>
</div>

<div class="card">
    <h2>🎫 ID Token Claims</h2>
    <p>These are the claims from your OIDC ID token:</p>
    <div class="token-box">{{ token_claims }}</div>
</div>
'''

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('profile'))
    return render_template_string(BASE_TEMPLATE, title='Home', content=HOME_CONTENT)

@app.route('/login')
def login():
    redirect_uri = url_for('callback', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route('/callback')
def callback():
    try:
        token = oauth.keycloak.authorize_access_token()
        user_info = token.get('userinfo')
        if user_info:
            session['user'] = user_info
            session['token'] = token
        return redirect(url_for('profile'))
    except Exception as e:
        return f'Authentication error: {str(e)}', 400

@app.route('/profile')
@login_required
def profile():
    user = session.get('user', {})
    token_claims = json.dumps(user, indent=2)
    content = render_template_string(PROFILE_CONTENT, user=user, token_claims=token_claims)
    return render_template_string(BASE_TEMPLATE, title='Profile', content=content)

@app.route('/logout')
def logout():
    session.clear()
    # Redirect to Keycloak logout
    logout_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout"
    return redirect(logout_url)

@app.route('/health')
def health():
    return {'status': 'healthy'}, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
