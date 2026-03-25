#!/bin/bash

BASE_URL="https://127.0.0.1:5001"
USERNAME="test"
PASSWORD="Test123!Strong"

echo "---- 1. Register User ----"
curl -sk $BASE_URL/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}"
echo -e "\n"

echo "---- 2. Login ----"

LOGIN_RESPONSE=$(curl -sk $BASE_URL/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")

echo "$LOGIN_RESPONSE"
echo -e "\n"

# Wait a short time to avoid IP rate limit
sleep 1

# Check if MFA is required or invalid
if echo "$LOGIN_RESPONSE" | grep -Eq "Invalid MFA code|MFA required"; then
  echo "MFA required."
  read -p "Enter TOTP code: " TOTP_CODE

  # Wait a short time before retrying
  sleep 1

  LOGIN_RESPONSE=$(curl -sk $BASE_URL/api/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\",\"totpCode\":\"$TOTP_CODE\"}")

  echo "$LOGIN_RESPONSE"
  echo -e "\n"
fi

if ! echo "$LOGIN_RESPONSE" | jq . >/dev/null 2>&1; then
  echo "Login did not return JSON:"
  echo "$LOGIN_RESPONSE"
  exit 1
fi

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.accessToken')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "Failed to extract token"
  exit 1
fi

echo "TOKEN: $TOKEN"
echo -e "\n"

echo "---- 3. Setup TOTP ----"
TOTP_RESPONSE=$(curl -sk $BASE_URL/api/totp/setup-totp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"username\":\"$USERNAME\"}")

echo "Raw TOTP response: $TOTP_RESPONSE"

# Parse JSON safely
TOTP_SECRET=$(echo "$TOTP_RESPONSE" | jq -r '.secret')
QR_CODE=$(echo "$TOTP_RESPONSE" | jq -r '.qrCodeUrl')
BACKUP_CODES=$(echo "$TOTP_RESPONSE" | jq -r '.backupCodes | join(", ")')

echo "TOTP Secret: $TOTP_SECRET"
echo "QR Code URL: $QR_CODE"
echo "Backup Codes: $BACKUP_CODES"

echo "Scan the QR or enter the secret in your authenticator app."
read -p "Enter TOTP code from your authenticator: " TOTP_CODE

echo "---- 4. Login with MFA ----"
LOGIN_MFA_RESPONSE=$(curl -sk $BASE_URL/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\",\"totpCode\":\"$TOTP_CODE\"}")

echo "$LOGIN_MFA_RESPONSE"

# Extract the new access token after MFA login
TOKEN=$(echo "$LOGIN_MFA_RESPONSE" | jq -r '.accessToken')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "Failed to extract token after MFA login"
  exit 1
fi

echo "MFA Login TOKEN: $TOKEN"
echo -e "\n"

echo "---- 5. Change Password ----"
NEW_PASSWORD="StrongestEverEverEver123123123!!!!@@@@"

curl -sk $BASE_URL/api/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"OldPassword\":\"$PASSWORD\",\"NewPassword\":\"$NEW_PASSWORD\"}"

echo -e "\nDone."