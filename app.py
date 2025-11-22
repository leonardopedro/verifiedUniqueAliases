import os
import threading
from flask import Flask, request, jsonify
import requests
from jose import jwt
from jose.constants import ALGORITHMS
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# --- Configuration Constants ---
ATTESTATION_ENDPOINT_URL = "http://169.254.169.254/acc/tdx/ccel"
PAYPAL_TOKEN_URL = "https://api-m.sandbox.paypal.com/v1/oauth2/token"
PAYPAL_USERINFO_URL = "https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1"
MAX_REQUESTS_PER_SESSION = 30

# --- In-Memory, Thread-Safe State ---
class AppState:
    def __init__(self):
        self.counter = 0
        self.processed_ids = set()
        self.lock = threading.Lock()

app = Flask(__name__)
app_state = AppState()

# --- Load Secrets from Key Vault at Startup ---
try:
    key_vault_url = "airmadeCocoVault.azure.net"
        
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

    # Fetch all secrets
    paypal_client_id = "ARDDrFepkPcuh-bWdtKPLeMNptSHp2BvhahGiPNt3n317a-Uu68Xu4c9F_4N0hPI5YK60R3xRMNYr-B0"
    paypal_client_secret = secret_client.get_secret("PaypalClientSecret").value
    signing_key_pem = secret_client.get_secret("MyWebAppSigningKey").value
    
    print("Successfully loaded all secrets from Key Vault.")

except Exception as e:
    # If secrets fail to load, the app cannot run.
    print(f"FATAL: Could not load secrets from Key Vault: {e}")
    # In a real scenario, you'd have a more robust exit/health check fail.
    paypal_client_secret, signing_key_pem = None, None


@app.route('/callback')
def paypal_callback():
    global app_state, paypal_client_id, paypal_client_secret, signing_key_pem

    # 1. Check if secrets were loaded
    if not paypal_client_secret:
        return "Application is not configured correctly. Secrets are missing.", 500

    # 2. Check and increment request counter (thread-safe)
    with app_state.lock:
        if app_state.counter >= MAX_REQUESTS_PER_SESSION:
            return "Service usage limit for this session has been reached.", 429
        
    # 3. Get authorization code from request
    auth_code = request.args.get('code')
    if not auth_code:
        return "Missing authorization code.", 400

    try:
        # 4. Exchange code for access token
        token_response = requests.post(
            PAYPAL_TOKEN_URL,
            auth=(paypal_client_id, paypal_client_secret),
            headers={'Accept': 'application/json'},
            data={'grant_type': 'authorization_code', 'code': auth_code}
        )
        token_response.raise_for_status()
        access_token = token_response.json()['access_token']

        # 5. Get User Info
        user_info_response = requests.get(
            PAYPAL_USERINFO_URL,
            headers={'Authorization': f'Bearer {access_token}'}
        )
        user_info_response.raise_for_status()
        user_info = user_info_response.json()
        paypal_user_id = user_info.get('user_id')

        if not paypal_user_id:
            return "Could not retrieve PayPal User ID.", 500

        # 6. Check if user has already been processed (thread-safe)
        with app_state.lock:
            if paypal_user_id in app_state.processed_ids:
                return "This PayPal account has already been processed in this session.", 409
        
        # --- All checks passed, proceed with attestation and signing ---

        # 7. Get Azure Attestation token
        attestation_res = requests.get(ATTESTATION_ENDPOINT_URL, headers={'Content-Type': 'application/json'})
        attestation_res.raise_for_status()
        # The real token is inside a nested structure, but we'll simplify here
        attestation_token = attestation_res.json().get('report')

        # 8. Create the signed HTML payload
        html_content = (
            f"<html><head><title>Welcome!</title></head><body>"
            f"<h1>User Info Verified</h1><pre>{user_info}</pre>"
            f"<h2>Execution Attestation</h2><p>This proves the code ran on secure hardware.</p>"
            f"<textarea readonly rows='10' cols='80'>{attestation_token}</textarea>"
            f"</body></html>"
        )
        
        claims = {'html': html_content}
        signed_jwt = jwt.encode(claims, signing_key_pem, algorithm=ALGORITHMS.ES256K)

        # 9. Finalize state update on success
        with app_state.lock:
            app_state.processed_ids.add(paypal_user_id)
            app_state.counter += 1

        return f"""
            <html><body><h1>Signed Response Received</h1>
            <p>The following is a signed JWT. A client application can verify it using the public key and then render the HTML content inside.</p>
            <textarea readonly rows='15' cols='100'>{signed_jwt}</textarea>
            </body></html>
        """, 200

    except requests.exceptions.HTTPError as e:
        return f"An error occurred with PayPal API: {e.response.text}", 502
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}", 500

if __name__ == '__main__':
    # Gunicorn will be used in production
    app.run(host='0.0.0.0', port=8000)