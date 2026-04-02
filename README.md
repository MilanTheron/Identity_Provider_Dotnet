# Custom Identity Provider — Implementation Status & Checklist

**Legend**: ✅ = Implemented | ⏳ = In Progress | ❌ = TODO | ❓ = Needs Review

---

## 1. Core Authentication Hardening
### Concepts to Learn
- Password hashing strategies (Argon2, bcrypt tuning)
- Timing attacks and constant-time comparisons
- User enumeration prevention
- Secure credential validation flows

### Implementation Status
- ✅ Use strong hashing (Argon2id with 5 iterations)
- ✅ Ensure constant-time password comparison
- ✅ Return generic error messages for login failures
- ✅ Add delay on failed authentication attempts
- ✅ Enforce password policy (length, complexity, entropy)
- ✅ Check passwords against known breaches (Have I Been Pwned API)

**Files**: `PasswordService.cs`

---

## 2. Token System (JWT + Refresh Tokens)
### Concepts to Learn
- JWT structure (header, payload, signature)
- Standard claims: iss, aud, exp, nbf, sub
- Token signing (HMAC vs RSA)
- Token expiration strategies
- Refresh token rotation
- Token replay attacks

### Implementation Status
- ✅ Use short-lived access tokens
- ✅ Implement refresh token rotation
- ✅ Store refresh tokens securely
- ✅ Detect refresh token reuse and revoke session chain
- ✅ Include proper claims validation in all consumers
- ✅ Store (username, key) tuples
- ✅ Authenticate users via passkey

**Files**: `TokenService.cs`, `RefreshToken.cs`, `AuthController.cs`, `Program.cs`

---

## 3. OAuth2 Authorization Server
### Concepts to Learn
- OAuth2 flows (Authorization Code + PKCE)
- Roles: Resource Owner, Client, Authorization Server
- Redirect URI validation
- Scope and consent handling
- PKCE (code challenge / verifier)

### Implementation Status
- ✅ Build /authorize endpoint (code issuance)
- ✅ Build /token endpoint (code → token exchange)
- ✅ Enforce strict redirect URI matching
- ✅ Implement PKCE verification
- ✅ Store authorization codes securely (short-lived, one-time use)

**Files**: `TokenService.cs`, `AuthController.cs`, `TokenController.cs`

---

## 4. OpenID Connect (OIDC)
### Concepts to Learn
- ID Token structure and purpose
- OIDC scopes (openid, profile, email)
- Discovery document (.well-known/openid-configuration)
- JWKS (JSON Web Key Set)

### Implementation Status
- ✅ Issue ID tokens (JWT with user identity claims)
- ✅ Add /.well-known/openid-configuration endpoint
- ✅ Add /.well-known/jwks.json endpoint
- ✅ Include proper claims (sub, email, etc.)
- ✅ Sign tokens using asymmetric keys (RSA)

#### Setup keys: (might want to use cloudflare/Azure/AWS for this in production, but for local testing we can generate our own keys)
```bash
mkdir -p keys
openssl genpkey -algorithm RSA -out keys/private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/private.pem -out keys/public.pem
```

**Files**: `TokenService.cs`, `SecurityService.cs`, `TokenController.cs`, `WellKnownController.cs`

---

## 5. Login/Register Web Page
### Concepts to Learn
- Secure form handling (CSRF protection, input validation)
- Authentication UX patterns (login vs register flows)
- OAuth2 Authorization Code flow integration (PKCE, redirect handling)
- Safe redirect handling (prevent open redirects)
- Session/context preservation during auth flows
- Frontend state management (SPA or server-rendered)

### Implementation Status
- ❌ Create unified `/auth` page (login + register UI)
- ❌ Add form validation (client + server side)
- ❌ Integrate with `/login` and `/register` endpoints
- ✅ Handle `/authorize` flow (preserve OAuth params: client_id, redirect_uri, state, PKCE)
- ❌ Resume authorization flow after authentication
- ❌ Implement optional consent screen
- ❌ Add CSRF protection
- ❌ Prevent open redirect vulnerabilities
- ❌ Add basic rate limiting protection on UI actions

**Status**: 

--- `OAuthController.cs` (backend ready, UI missing)

## 6. Email Verification
### Concepts to Learn
- Token-based verification flows
- Email spoofing & phishing considerations
- Expiring, single-use tokens

### Implementation Status
- ✅ Generate email verification token
- ✅ Send email with verification link
- ❌ Store hashed token with expiration
- ❌ Mark email as verified upon confirmation
- ❌ Prevent login until email is verified

**Status**: Not started

---

## 7. Password Reset Flow
### Concepts to Learn
- Secure reset token generation
- Token expiration and single use
- Abuse prevention (rate limiting)

### Implementation Status
- ✅ Create "forgot password" endpoint
- ✅ Generate and email reset token
- ❌ Validate token before allowing password change
- ✅ Invalidate all sessions after password change

**Status**: `EmailController.cs`, `AuthController.cs`

---

## 8. Multi-Factor Authentication (MFA)
### Concepts to Learn
- TOTP algorithm basics (RFC 6238)
- Clock drift handling
- Backup codes strategy

### Implementation Status
- ✅ TOTP verification system
- ✅ QR code generation for authenticator apps
- ✅ Generate and hash backup codes (10 codes, 12 characters, 4 Argon2id iterations)
- ✅ Allow TOTP or backup code verification during login
- ✅ Invalidate used backup codes
- ✅ Clock drift handling
- ❌ Email/SMS OTP fallback

**Files**: `BackupCodeService.cs`, `AuthController.cs`

---

## 9. Device Tracking & Session Management
### Concepts to Learn
- Device fingerprinting basics (limitations)
- Session tracking vs stateless auth
- User agent + IP tracking

### Implementation Status
- ✅ IP-based rate limiting
- ❌ Device fingerprinting
- ❌ Store device info (IP, user-agent, timestamps)
- ❌ Associate refresh tokens with devices
- ❌ Allow users to view active sessions
- ❌ Allow revocation per device

**Status**: Not started

---

## 10. Anomaly Detection (Basic)
### Concepts to Learn
- Risk-based authentication
- Geo-IP basics
- "Impossible travel" logic

### Implementation Status (might user cloudflare for geo-IP and anomaly detection)
- ❌ Detect new IP or unusual location
- ❌ Flag rapid location changes
- ❌ Trigger additional verification (MFA)
- ❌ Log suspicious activity

**Status**: Not started

---

## 11. Brute Force Protection (might use cloudflare except for account lockout)
### Concepts to Learn
- Rate limiting strategies (IP vs account) (/login and /token endpoints)
- Lockout policies and trade-offs
- Credential stuffing defense

### Implementation Status
- ✅ Rate limiting per IP (10 attempts per minute)
- ✅ Track failed login attempts per user
- ✅ Account lockout (5 failed attempts → 15 min lockout)
- ✅ Progressive difficulty (exponential backoff)
- ✅ Reset counter on successful login
- ❌ Combine with CAPTCHA - *Not implemented*
- ✅ Distributed rate limiting

**Files**: `SecurityService.cs`, `AuthController.cs`, `Program.cs`

---

## 12. JWT Invalidation Strategy
### Concepts to Learn
- Stateless vs stateful auth trade-offs
- Token revocation patterns
- Session versioning

### Implementation Status
- ✅ Use short-lived access tokens
- ✅ Maintain refresh token store
- ✅ Revoke tokens on logout
- ✅ Revoke tokens on password change
- ✅ Detect and handle token reuse
- ⏳ Token blacklist - *Uses revocation flag instead*
- ❌ Distributed cache support (Redis)

**Files**: `RefreshToken.cs`, `AuthController.cs`

---

## 13. Security Headers & HTTPS (might use cloudflare except for CSP)
### Concepts to Learn
- HTTPS enforcement
- HSTS (HTTP Strict Transport Security)
- CSP (Content Security Policy)

### Implementation Status
- ✅ Enforce HTTPS everywhere
- ✅ Add HSTS headers
- ✅ Configure CSP, X-Frame-Options, X-Content-Type-Options
- ✅ Disable insecure HTTP methods if unused

**Files**: `Program.cs`

---

## 14. Logging & Audit Trail
### Concepts to Learn
- Security event logging
- Audit trail design
- Log integrity

### Implementation Status
- ⏳ Log login attempts (success/failure)
- ⏳ Log password changes, MFA events
- ⏳ Log token issuance and revocation
- ⏳ Store logs securely and query efficiently

**Status**: `LoggingConfig.cs`, `Services`

---

## 15. Concurrency & Edge Cases
### Concepts to Learn
- Race conditions in auth systems
- Idempotency
- Distributed systems issues

### Implementation Status
- ✅ Thread-safe rate limiting (ConcurrentDictionary)
- ✅ Handle concurrent refresh requests safely - *Needs testing*
- ⏳ Prevent duplicate token issuance - *Possible edge case*
- ✅ Ensure atomic DB operations
- ❌ Handle partial failures (e.g., token issued but DB save fails)

**Files**: `SecurityService.cs`

---

## 16. Testing & Validation
### Concepts to Learn
- Security testing (fuzzing, abuse cases)
- Integration testing auth flows
- Token validation testing

### Implementation Status
- ⏳ Unit tests for services
- ⏳ Integration tests for auth flows
- ⏳ Simulate attack scenarios
- ❌ Validate token expiration and revocation
- ❌ Test MFA edge cases (clock drift, reuse)

##### Test command used:
```bash
dotnet test
```

**Status**: Not started

---

## Next Steps (Priority Order)

### HIGH PRIORITY
1. **Logging & Audit Trail** - Track all auth events
3. **maybe change (username, key) tuples to (email, key)** - More standard and allows for email verification

### MEDIUM PRIORITY
5. **Email Verification** - Add email service integration
6. **Password Reset Flow** - Complete implementation
9. **Device Tracking** - Session per device management

### LOW PRIORITY (Future)
10. **Anomaly Detection** - Geo-IP, impossible travel
12. **Redis Integration** - Distributed rate limiting

---

### Different curl request for testing(outdated):
1. Register a new user:
```bash
curl -k https://127.0.0.1:5001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"Test123!Strong"}'
```
2. Login with the new user:
```bash
curl -k https://127.0.0.1:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"Test123!Strong"}'
```
3. Enable MFA for the user (replace #TOKEN with actual JWT token):
```bash
curl -k https://127.0.0.1:5001/api/totp/setup-totp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer #TOKEN" \
  -d '{"username":"test"}'
```
4. Login with MFA (replace CODE with actual TOTP code):
```bash
curl -k https://127.0.0.1:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"Test123!Strong","totpCode":"CODE"}'
```
5. Change password (replace #TOKEN with actual JWT token):
```bash
curl -k https://127.0.0.1:5001/api/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer #TOKEN" \
  -d '{"OldPassword":"Test123!Strong","NewPassword":"StrongestEverEverEver123123123!!!!@@@@"}'
```

---

### Endpoint List: 
**Command: (command: grep -rnE "^\s\*\[Route|^\s\*\[Http(Get|Post|Put|Delete|Patch)" .)**
- "register"
- "login"
- "logout"
- "change-password"

- "/Error"
- "/Error/{statusCode}"

- "me"

- "authorize"
-  "token"

- "token/refresh"

- "setup-totp"

- "/webauthn/register/start"
- "/webauthn/register/finish"
- "/webauthn/login/start"
- "/webauthn/login/finish"

- "openid-configuration"
- "jwks"