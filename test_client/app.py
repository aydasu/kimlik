from flask import Flask, request, redirect, session, render_template_string
import requests
import os
import secrets
from dotenv import load_dotenv
import time
from datetime import datetime

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Session configuration
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# OAuth configuration
CLIENT_ID = os.getenv('CLIENT_ID', '9a8282de8c17dc2cdf01dfd26e8c5f45')
CLIENT_SECRET = os.getenv('CLIENT_SECRET', 'ceda2ae65075d49d879398a7cd56dad45ce8ee699c9c906149464d2c34117894')
REDIRECT_URI = os.getenv('REDIRECT_URI', 'http://localhost:5000/callback')
AUTH_SERVER = os.getenv('AUTH_SERVER', 'http://localhost:8000')  # Change this to your OAuth server URL
AUTH_ENDPOINT = f"{AUTH_SERVER}/oauth.php"
TOKEN_ENDPOINT = f"{AUTH_SERVER}/oauth.php"  # Token endpoint is also oauth.php
API_ENDPOINT = f"{AUTH_SERVER}/api.php"

# HTML template for the home page
HOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>OAuth Test İstemcisi</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .button { 
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            display: inline-block;
        }
        .info { margin: 20px 0; padding: 10px; background-color: #f0f0f0; }
        .error { color: red; margin: 20px 0; }
        .token-info { word-break: break-all; }
    </style>
</head>
<body>
    <div class="container">
        <h1>OAuth Test İstemcisi</h1>
        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}
        {% if not session.get('access_token') %}
            <a href="/login" class="button">OAuth ile Giriş Yap</a>
        {% else %}
            <div class="info">
                <h3>Erişim Tokeni:</h3>
                <p class="token-info">{{ session.get('access_token') }}</p>
                <p><strong>Token Bitiş Zamanı:</strong> {{ (session.get('token_expires_at')|int)|datetime }}</p>
            </div>
            <div class="info">
                <h3>Yenileme Tokeni:</h3>
                <p class="token-info">{{ session.get('refresh_token') }}</p>
            </div>
            <div class="info">
                <h3>Kullanıcı Bilgileri:</h3>
                <pre>{{ user_info | tojson(indent=2) }}</pre>
            </div>
            <a href="/logout" class="button">Çıkış Yap</a>
        {% endif %}
    </div>
</body>
</html>
"""

# Add datetime filter
@app.template_filter('datetime')
def format_datetime(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

@app.route('/')
def home():
    user_info = None
    error = None
    
    # Check if token needs refresh
    if session.get('access_token') and session.get('token_expires_at'):
        if time.time() >= session['token_expires_at'] - 300:  # Refresh 5 minutes before expiry
            if not refresh_access_token():
                session.clear()
                return redirect('/login')
    
    if session.get('access_token'):
        # Fetch user info using the access token
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.get(f"{API_ENDPOINT}/user", headers=headers)
        if response.status_code == 200:
            user_info = response.json()
        else:
            error = "Kullanıcı bilgileri alınamadı"
            session.clear()
    
    return render_template_string(HOME_TEMPLATE, user_info=user_info, error=error)

@app.route('/login')
def login():
    # Check if we already have an access token
    if session.get('access_token'):
        return redirect('/')
        
    # Generate state parameter for security
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    
    # Generate OAuth authorization URL
    auth_url = f"{AUTH_ENDPOINT}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state={state}"
    print(f"Yetkilendirme URL'sine yönlendiriliyor: {auth_url}")
    return redirect(auth_url)

@app.route('/callback')
def callback():
    error = request.args.get('error')
    if error:
        print(f"OAuth hatası alındı: {error}")
        session.clear()
        return render_template_string(HOME_TEMPLATE, error=f"Yetkilendirme başarısız: {error}")
    
    code = request.args.get('code')
    state = request.args.get('state')
    
    print(f"Kod ile geri çağrı alındı: {code}")
    print(f"Durum alındı: {state}")
    print(f"Oturum durumu: {session.get('oauth_state')}")
    
    if not code or not state:
        print("Kod veya durum parametreleri eksik")
        session.clear()
        return render_template_string(HOME_TEMPLATE, error="Gerekli parametreler eksik")
    
    # Verify state parameter
    if state != session.get('oauth_state'):
        print(f"Durum uyuşmazlığı - Alınan: {state}, Beklenen: {session.get('oauth_state')}")
        session.clear()
        return render_template_string(HOME_TEMPLATE, error="Geçersiz durum parametresi")
    
    # Clear state from session
    session.pop('oauth_state', None)

    # Exchange authorization code for access token
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI
    }

    print(f"Token isteği gönderiliyor: {TOKEN_ENDPOINT}")
    print(f"Token istek verileri: {token_data}")
    
    try:
        response = requests.post(TOKEN_ENDPOINT, data=token_data)
        print(f"Token yanıt durumu: {response.status_code}")
        print(f"Token yanıt içeriği: {response.text}")
        
        if response.status_code == 200:
            token_response = response.json()
            session['access_token'] = token_response.get('access_token')
            session['refresh_token'] = token_response.get('refresh_token')
            session['token_expires_at'] = time.time() + token_response.get('expires_in', 3600)
            return redirect('/')
        else:
            error_msg = "Erişim tokeni alınamadı"
            try:
                error_data = response.json()
                if 'error' in error_data:
                    error_msg = f"Erişim tokeni alınamadı: {error_data['error']}"
                    print(f"Hata detayları: {error_data}")
                    # If we get invalid_grant, clear session and show error
                    if error_data['error'] == 'invalid_grant':
                        session.clear()
                        return render_template_string(HOME_TEMPLATE, error="Yetkilendirme kodu süresi dolmuş veya zaten kullanılmış. Lütfen tekrar giriş yapmayı deneyin.")
            except Exception as e:
                print(f"Yanıt ayrıştırma hatası: {e}")
                print(f"Ham yanıt: {response.text}")
            session.clear()
            return render_template_string(HOME_TEMPLATE, error=error_msg)
    except requests.exceptions.RequestException as e:
        print(f"İstek başarısız: {e}")
        session.clear()
        return render_template_string(HOME_TEMPLATE, error="Yetkilendirme sunucusuna bağlanılamadı")

def refresh_access_token():
    if not session.get('refresh_token'):
        return False
    
    token_data = {
        'grant_type': 'refresh_token',
        'refresh_token': session['refresh_token'],
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    
    try:
        response = requests.post(TOKEN_ENDPOINT, data=token_data)
        if response.status_code == 200:
            token_response = response.json()
            session['access_token'] = token_response.get('access_token')
            session['refresh_token'] = token_response.get('refresh_token')
            session['token_expires_at'] = time.time() + token_response.get('expires_in', 3600)
            return True
    except:
        pass
    
    return False

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True) 