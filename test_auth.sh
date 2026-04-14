#!/bin/bash

BASE="http://localhost:5000"

echo "=== Register ==="
REGISTER_RESP=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$BASE/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"StrongPass1tyujsqdqs54===23!"}')

echo "$REGISTER_RESP"
echo -e "\n"

read -p "Verify email manually then press ENTER to continue..."

echo "=== Login (valid) ==="
LOGIN_RESP=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"StrongPass1tyujsqdqs54===23!"}' \
  -c cookies.txt)

echo "$LOGIN_RESP"
echo -e "\n"

echo "=== Wrong password timing ==="
WRONG=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}\nTime: %{time_total}s\n" -o /dev/null \
  -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"wrong"}')

echo "$WRONG"
echo -e "\n"

echo "=== Fake user timing ==="
FAKE=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}\nTime: %{time_total}s\n" -o /dev/null \
  -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"fake@example.com","password":"whatever"}')

echo "$FAKE"
echo -e "\n"

echo "=== Brute force simulation ==="
for i in {1..6}; do
  RES=$(curl -k -s -w "HTTP:%{http_code} TIME:%{time_total}s\n" -o /dev/null \
    -X POST "$BASE/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong"}')
  echo "Attempt $i: $RES"
done
echo -e "\n"

echo "=== Logout (session) ==="
LOGOUT_RESP=$(curl -i -k -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$BASE/api/auth/logout/session" \
  -b cookies.txt)

echo "$LOGOUT_RESP"
echo -e "\n"

echo "=== Security headers ==="
curl -i "$BASE/api/auth/login"