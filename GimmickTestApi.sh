#!/bin/bash

BASE_URL="https://127.0.0.1:5001"
USERNAME="test"
PASSWORD="Test123!Strong"
NEW_PASSWORD="StrongestEverEverEver123123123!!!!@@@@"

# --- 1. Register ---
echo "---- Register ----"
curl -sk $BASE_URL/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}"
echo -e "\n"

# --- 2. Login (no MFA yet) ---
echo "---- Login ----"
LOGIN_RESPONSE=$(curl -sk $BASE_URL/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.AccessToken')

echo "TOKEN: $TOKEN"
echo

# --- 3. Setup TOTP ---
echo "---- Setup TOTP ----"
TOTP_SETUP_RESPONSE=$(curl -sk $BASE_URL/api/totp/setup-totp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{}")

echo "$TOTP_SETUP_RESPONSE"

TOTP_SECRET=$(echo "$TOTP_SETUP_RESPONSE" | jq -r '.Secret')
echo "Secret: $TOTP_SECRET"
echo

# --- 4. Generate TOTP ---
TOTP_CODE=$(oathtool --totp -b "$TOTP_SECRET")
echo "TOTP CODE: $TOTP_CODE"

# --- 5. Login WITH MFA ---
echo "---- Login with MFA ----"
LOGIN_MFA_RESPONSE=$(curl -sk $BASE_URL/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\",\"totpCode\":\"$TOTP_CODE\"}")

echo "$LOGIN_MFA_RESPONSE"

TOKEN=$(echo "$LOGIN_MFA_RESPONSE" | jq -r '.AccessToken')

echo "MFA TOKEN: $TOKEN"
echo

# --- 6. Change Password ---
echo "---- Change Password ----"
curl -sk $BASE_URL/api/auth/change-password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"oldPassword\":\"$PASSWORD\",\"newPassword\":\"$NEW_PASSWORD\"}"

echo -e "\nDone."