#!/bin/bash

BASE_URL="https://127.0.0.1:5001"
USERNAME="testuser2"
PASSWORD="Test123!Strong"

echo "---- Register User ----"
curl -sk $BASE_URL/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}"
echo -e "\n"

echo "---- Login ----"
LOGIN_RESPONSE=$(curl -sk $BASE_URL/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")

echo "$LOGIN_RESPONSE"
echo -e "\n"

# Extract token
TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.accessToken.result // .accessToken')

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
  echo "Login failed or requires MFA. Full response:"
  echo "$LOGIN_RESPONSE"
  exit 1
fi

echo "TOKEN: $TOKEN"
echo

### ---------------------
### OAuth Authorization Test
### ---------------------
echo "---- OAuth Authorize (PKCE) ----"

# Generate PKCE challenge
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/")
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')

# Example request
REDIRECT_URI="https://example.com/callback"
CLIENT_ID="testclient123"
STATE="xyz123"
TENANT="mytenant"
SCOPE="openid profile email"

AUTH_URL="$BASE_URL/api/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&state=$STATE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&tenant=$TENANT&scope=$SCOPE"

# Call authorize endpoint
echo "Opening authorize URL (simulate browser redirect)..."
curl -sk -L -H "Authorization: Bearer $TOKEN" "$AUTH_URL"
echo
echo "Capture the ?code= from redirect URL manually for token exchange."

# Example token exchange after getting code (replace CODE_HERE)
# echo "---- OAuth Token Exchange ----"
# curl -sk $BASE_URL/api/oauth/token \
#   -X POST -H "Content-Type: application/x-www-form-urlencoded" \
#   -d "grant_type=authorization_code&client_id=$CLIENT_ID&code=CODE_HERE&redirect_uri=$REDIRECT_URI&code_verifier=$CODE_VERIFIER"

### ---------------------
### WebAuthn Registration Test
### ---------------------
echo "---- WebAuthn Registration Start ----"
REG_START=$(curl -sk $BASE_URL/api/webauthn/register/start \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\"}")

echo "$REG_START"
echo "Send client response to finish registration manually..."
# Read client response from your frontend / authenticator
read -p "Paste WebAuthn register finish client response JSON: " CLIENT_RESPONSE

echo "---- WebAuthn Registration Finish ----"
curl -sk $BASE_URL/api/webauthn/register/finish \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"clientResponse\":$CLIENT_RESPONSE}"
echo

### ---------------------
### WebAuthn Login Test
### ---------------------
echo "---- WebAuthn Login Start ----"
LOGIN_START=$(curl -sk $BASE_URL/api/webauthn/login/start \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\"}")

echo "$LOGIN_START"
echo "Send client response to finish login manually..."
read -p "Paste WebAuthn login finish client response JSON: " CLIENT_LOGIN_RESPONSE

echo "---- WebAuthn Login Finish ----"
curl -sk $BASE_URL/api/webauthn/login/finish \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"clientResponse\":$CLIENT_LOGIN_RESPONSE}"
echo