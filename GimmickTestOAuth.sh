#!/bin/bash
set -e

BASE_URL="https://localhost:5001"
USERNAME="testuser2"
PASSWORD="Test123!Strong"

CLIENT_ID="myclient"
REDIRECT_URI="https://localhost:5002/callback"
STATE="xyz123"
SCOPE="openid profile email"
TENANT="mytenant"

fail() {
  echo "❌ $1"
  exit 1
}

pass() {
  echo "✅ $1"
}

echo "---- Register User ----"
REGISTER_RESPONSE=$(curl -sk -w "\n%{http_code}" "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")

REGISTER_BODY=$(echo "$REGISTER_RESPONSE" | head -n -1)
REGISTER_CODE=$(echo "$REGISTER_RESPONSE" | tail -n1)

if [[ "$REGISTER_CODE" != "200" && "$REGISTER_CODE" != "201" ]]; then
  fail "Register failed: $REGISTER_BODY"
fi

pass "User registered (or already exists)"

echo
echo "---- Login ----"
LOGIN_RESPONSE=$(curl -sk -w "\n%{http_code}" "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")

LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | head -n -1)
LOGIN_CODE=$(echo "$LOGIN_RESPONSE" | tail -n1)

if [[ "$LOGIN_CODE" != "200" ]]; then
  fail "Login failed: $LOGIN_BODY"
fi

if ! echo "$LOGIN_BODY" | jq . >/dev/null 2>&1; then
  fail "Login did not return valid JSON: $LOGIN_BODY"
fi

TOKEN=$(echo "$LOGIN_BODY" | jq -r '.accessToken')
if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
  fail "Access token extraction failed"
fi

REFRESH_TOKEN=$(echo "$LOGIN_BODY" | jq -r '.refreshToken')
pass "Login successful"

echo
echo "---- Generate PKCE ----"
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/")
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')
pass "PKCE verifier + challenge generated"

echo
echo "---- OAuth Authorize ----"
AUTH_RESPONSE=$(curl -sk --get -i \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "ClientId=$CLIENT_ID" \
  --data-urlencode "RedirectUri=$REDIRECT_URI" \
  --data-urlencode "ResponseType=code" \
  --data-urlencode "CodeChallenge=$CODE_CHALLENGE" \
  --data-urlencode "CodeChallengeMethod=S256" \
  --data-urlencode "Tenant=$TENANT" \
  --data-urlencode "Scope=$SCOPE" \
  --data-urlencode "State=$STATE" \
  "$BASE_URL/api/oauth/authorize")

LOCATION=$(echo "$AUTH_RESPONSE" | grep -i Location | awk '{print $2}' | tr -d '\r')
if [[ -z "$LOCATION" ]]; then
  fail "No redirect received from authorize endpoint"
fi
echo "$AUTH_RESPONSE" | head -n 10
echo "Redirect URL: $LOCATION"

CODE=$(echo "$LOCATION" | sed -n 's/.*code=\([^&]*\).*/\1/p')
RETURNED_STATE=$(echo "$LOCATION" | sed -n 's/.*state=\([^&]*\).*/\1/p')
if [[ -z "$CODE" ]]; then fail "Authorization code missing"; fi
if [[ "$RETURNED_STATE" != "$STATE" ]]; then fail "State mismatch (possible CSRF)"; fi
pass "Authorization successful"

echo
echo "---- Token Exchange ----"
TOKEN_RESPONSE=$(curl -sk "$BASE_URL/api/oauth/token" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{\"grantType\":\"authorization_code\",\"clientId\":\"$CLIENT_ID\",\"code\":\"$CODE\",\"redirectUri\":\"$REDIRECT_URI\",\"codeVerifier\":\"$CODE_VERIFIER\"}")

if ! echo "$TOKEN_RESPONSE" | jq . >/dev/null 2>&1; then
  fail "Token response not valid JSON: $TOKEN_RESPONSE"
fi

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.accessToken')
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refreshToken')

if [[ -z "$ACCESS_TOKEN" || "$ACCESS_TOKEN" == "null" ]]; then fail "Access token missing"; fi
if [[ -z "$REFRESH_TOKEN" || "$REFRESH_TOKEN" == "null" ]]; then fail "Refresh token missing"; fi

pass "Token exchange successful"
echo
echo "✅ FULL OAUTH FLOW WORKS"