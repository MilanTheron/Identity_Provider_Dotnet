# IDP Workflow Architecture & Flow Diagrams

This document provides visual representations of all authentication and authorization workflows.

## Summary

### ✅ Working Flows
- User Login (password validation, TOTP)
- Token Refresh (rotation + reuse detection)
- Password Reset (token-based)
- Logout (token revocation)
- OAuth2 Authorization
- TOTP Setup
- TOTP Fallback
- Email Verification
- WellKnown Discovery
- Rate Limiting
- Authorization Code scope tracking
- PKCE length validation
- Error handling consistency
- RefreshToken storage

---

## Summary Table: Request Types & Authentication

```
┌─────────────────────────────┬──────────────────┬──────────────────┐
│ Request Type                │ Authorization    │ Authentication   │
├─────────────────────────────┼──────────────────┼──────────────────┤
│ POST /auth/register         │ Public           │ None             │
│ POST /auth/login            │ Public           │ None             │
│ POST /auth/logout/session   │ Cookie or JWT    │ Authenticated    │
│ POST /webauthn/login/start  │ Public           │ None             │
│ POST /webauthn/login/finish │ Public           │ None             │
│ POST /webauthn/reg/start    │ JWT Required     │ Authenticated    │
│ POST /webauthn/reg/finish   │ JWT Required     │ Authenticated    │
│ GET  /email/verify-email    │ Public           │ None             │
│ POST /email/resend-verify   │ Public           │ None             │
│ POST /email/forgot-password │ Public           │ None             │
│ POST /email/reset-password  │ Public           │ None             │
│ GET  /oauth/authorize       │ Cookie Required  │ Session Needed   │
│ POST /oauth/token           │ Public           │ None (PKCE)      │
│ GET  /api/me                │ JWT or Cookie    │ Authenticated    │
│ POST /api/totp/setup        │ JWT Required     │ Authenticated    │
│ POST /api/token/refresh     │ Public           │ None (RT hash)   │
└─────────────────────────────┴──────────────────┴──────────────────┘

```

## Implementation Checklist

### ✅ Already Implemented

```
Authentication:
✅ /api/auth/register - User registration
✅ /api/auth/login - Password login with MFA support
✅ /api/auth/logout/session - Session logout (NEW)
✅ /api/auth/logout - Token logout + revoke

WebAuthn:
✅ /api/webauthn/register/start - Start registration
✅ /api/webauthn/register/finish - Finish registration
✅ /api/webauthn/login/start - Start login
✅ /api/webauthn/login/finish - Finish login (session)

Email & Recovery:
✅ /api/email/verify-email - Verify email
✅ /api/email/resend-verification - Resend verification
✅ /api/email/forgot-password - Request password reset
✅ /api/email/reset-password - Reset password + revoke tokens

MFA:
✅ TOTP setup & validation
✅ Backup codes (recovery)
✅ Fallback tokens
✅ Rate limiting on auth attempts

OAuth & JWT:
✅ /api/oauth/authorize - Authorization code flow
✅ /api/oauth/token - Token exchange (JWT + Refresh)
✅ /api/token/refresh - Refresh JWT
✅ SmartScheme - Cookie or JWT routing

Authorization:
✅ @[Authorize] - Requires authentication
✅ @[Authorize(Policy="AdminOnly")] - Admin only
✅ @[Authorize(Policy="RequireMfa")] - MFA required
✅ @[Authorize(Policy="SensitiveOperation")] - Sensitive ops

Security:
✅ Password hashing (Argon2)
✅ Token hashing (SHA256)
✅ Secure random generation
✅ Time-based comparison (prevents timing attacks)
✅ HttpOnly cookies
✅ Secure cookies (HTTPS only)
✅ SameSite=Lax (CSRF protection)
✅ JWT signature validation (RSA)
✅ JTI validation (prevent token replay)
✅ Email verification enforcement
✅ Token expiry validation
✅ User existence check
```

---

## User Registration & Email Verification Flow
```
┌─────────────────────────────────────────────────────────────────┐
│                      REGISTRATION FLOW                          │
└─────────────────────────────────────────────────────────────────┘

1. USER REGISTRATION
   ┌──────────────────┐
   │ User            │
   └────────┬─────────┘
            │ POST /api/auth/register
            │ { email, password }
            ↓
   ┌──────────────────────────────────┐
   │ AuthController.Register()        │
   │ - Validate email unique          │
   │ - Check password strength        │
   │ - Check HIBP                     │
   │ - Hash password (Argon2id)       │
   │ - Generate email token           │
   └────────┬─────────────────────────┘
            │ Create User (EmailVerified=false)
            ↓
   ┌──────────────────────────────────┐
   │ Database                         │
   │ User {                           │
   │   Id: GUID                       │
   │   Email: "user@example.com"      │
   │   PasswordHash: argon2_hash      │
   │   EmailVerified: false           │
   │   EmailVerificationTokenHash: XX │
   │   EmailVerificationTokenExpiry:  │
   │   DateTime.UtcNow + 24h          │
   │ }                                │
   └────────┬─────────────────────────┘
            │
            │ Send Email
            ↓
   ┌──────────────────────────────────┐
   │ SendEmailService                 │
   │ TO: user@example.com             │
   │ SUBJECT: Verify your email       │
   │ BODY: Click link:                │
   │ /api/email/verify-email          │
   │   ?token=RAW_TOKEN               │
   │   &userId=GUID                   │
   └──────────────────────────────────┘

2. USER CLICKS EMAIL LINK
   ┌──────────────────┐
   │ User clicks link │
   └────────┬─────────┘
            │ GET /api/email/verify-email
            │ ?token=RAW_TOKEN&userId=GUID
            ↓
   ┌──────────────────────────────────┐
   │ EmailController.VerifyEmail()    │
   │ - Check user exists              │
   │ - Check token not expired        │
   │ - Hash provided token            │
   │ - Compare with stored hash       │  (Constant-time comparison)
   │ - Set EmailVerified = true       │
   │ - Clear token & expiry           │
   └────────┬─────────────────────────┘
            │ Update User
            ↓
   ┌──────────────────────────────────┐
   │ Database                         │
   │ User.EmailVerified = TRUE        │
   └──────────────────────────────────┘

✅ EMAIL VERIFICATION COMPLETE
```

---

## 2. User Login Flow (Direct)

```
┌─────────────────────────────────────────────────────────────────┐
│                   LOGIN FLOW (SESSION-BASED)                    │
└─────────────────────────────────────────────────────────────────┘

1. SUBMIT LOGIN CREDENTIALS
   ┌──────────────┐
   │ User         │
   └──────┬───────┘
          │ POST /api/auth/login
          │ {
          │   email: "user@example.com"
          │   password: "MyPassword123!"
          │   totpCode?: "123456"             [If MFA enabled]
          │   backupCode?: "ABC123XYZ"        [If using backup]
          │ }
          ↓
   ┌─────────────────────────────────────────┐
   │ AuthController.Login()                  │
   │ 1. Get client IP                        │
   │ 2. Find user by email                   │
   │ 3. Check email verified                 │
   │ 4. Verify password (Argon2id)           │
   │ 5. If MFA enabled:                      │
   │    - Validate TOTP code OR              │
   │    - Validate & consume backup code     │
   │ 6. Create ClaimsPrincipal               │
   │ 7. Sign in with cookie                  │
   └──────┬────────────────────────────────────┘
          │
          │ ✅ Login successful
          ↓
   ┌─────────────────────────────────────────┐
   │ Create Session Cookie Claims:           │
   │                                         │
   │ var claims = new List<Claim>            │
   │ {                                       │
   │   new Claim("sub", user.Id.ToString()), │
   │   new Claim("amr", "pwd"),              │
   │   new Claim("mfa", mfaVerified ? "true" │
   │             : "false")                  │
   │ };                                      │
   │                                         │
   │ var identity = new ClaimsIdentity(      │
   │   claims, "AuthScheme"                  │
   │ );                                      │
   │ var principal = new ClaimsPrincipal(    │
   │   identity                              │
   │ );                                      │
   │                                         │
   │ await HttpContext.SignInAsync(          │
   │   "AuthScheme", principal               │
   │ );                                      │
   └──────┬────────────────────────────────────┘
          │
          │ Set-Cookie header with:
          │ - Name: .AspNetCore.Cookies
          │ - HttpOnly: true (JS cannot access)
          │ - Secure: true (HTTPS only)
          │ - SameSite: Lax (CSRF protection)
          │ - Path: /
          │ - Expires: Session or 30 days
          │
          ↓
   ┌─────────────────────────────────────────┐
   │ Return to Client:                       │
   │ {                                       │
   │   "message": "authenticated"            │
   │ }                                       │
   │                                         │
   │ Header: Set-Cookie: .AspNetCore...      │
   └─────────────────────────────────────────┘

✅ LOGIN COMPLETE - Session Cookie Created
   User is now authenticated for /oauth/authorize
```

---

## 2b. WebAuthn Login Flow - Creates Session Cookie

```
┌─────────────────────────────────────────────────────────────────┐
│                WEBAUTHN LOGIN FLOW (BIOMETRIC)                  │
│     (Preferred method when available - Face ID / Touch ID)      │
└─────────────────────────────────────────────────────────────────┘

1. START WEBAUTHN LOGIN
   ┌──────────────┐
   │ User         │
   └──────┬───────┘
          │ POST /api/webauthn/login/start
          │ { email: "user@example.com" }
          ↓
   ┌──────────────────────────────────────┐
   │ WebAuthnController.StartWebAuthnLogin()
   │ [AllowAnonymous]                     │
   │                                      │
   │ 1. Find user by email                │
   │ 2. Get WebAuthn credentials list     │
   │ 3. If no credentials:                │
   │    Return empty {}                   │
   │    (Frontend offers password fallback)
   │ 4. Generate challenge (32 bytes)     │
   │ 5. Return options with:              │
   │    - challenge                       │
   │    - allowCredentials                │
   │    - timeout: 60000ms                │
   │    - userVerification: preferred     │
   └──────┬────────────────────────────────┘
          │
          │ Return:
          ├─ If credentials exist:
          │  { challenge, allowCredentials, ... }
          │
          └─ If NO credentials:
             {} (empty response)
          
          ↓
   ┌──────────────────────────────────────┐
   │ Browser: Prompts for Biometric       │
   │ (Face ID / Windows Hello / YubiKey)  │
   │                                      │
   │ User: Authenticates with biometric   │
   │                                      │
   │ Device: Signs challenge with private │
   │ key stored in authenticator          │
   └──────┬────────────────────────────────┘
          │
          │ POST /api/webauthn/login/finish
          │ {
          │   clientResponse: {
          │     id: credential_id,
          │     type: "public-key",
          │     response: {
          │       authenticatorData: base64,
          │       clientDataJSON: base64,
          │       signature: base64
          │     }
          │   }
          │ }
          ↓
   ┌──────────────────────────────────────┐
   │ WebAuthnController.FinishWebAuthnLogin()
   │ [AllowAnonymous]                     │
   │                                      │
   │ 1. Decode credential ID              │
   │ 2. Find stored credential by ID      │
   │ 3. Find user by credential           │
   │ 4. Validate signature:               │
   │    - Fetch stored public key         │
   │    - Verify signature matches        │
   │    - Check authenticator data        │
   │    - Verify user presence flag       │
   │ 5. Create ClaimsPrincipal            │
   │ 6. Sign in with cookie               │
   └──────┬────────────────────────────────┘
          │
          │ ✅ Signature valid
          │
          │ Create Session Cookie Claims:
          │ var claims = new List<Claim>
          │ {
          │   new Claim("sub", user.Id),
          │   new Claim("amr", "webauthn")
          │ };
          │
          │ await HttpContext.SignInAsync(
          │   "AuthScheme", principal
          │ );
          ↓
   ┌──────────────────────────────────────┐
   │ Return to Client:                    │
   │ {                                    │
   │   "message": "authenticated"         │
   │ }                                    │
   │                                      │
   │ Header: Set-Cookie: .AspNetCore...   │
   └──────────────────────────────────────┘

✅ WEBAUTHN LOGIN COMPLETE - Session Cookie Created
   User is now authenticated for /oauth/authorize
```

---

## 3. OAuth2 Authorization Code Flow (PKCE)

```
┌─────────────────────────────────────────────────────────────────┐
│            OAUTH2 AUTHORIZATION CODE FLOW WITH PKCE             │
│    (User must first be authenticated via session cookie)        │
└─────────────────────────────────────────────────────────────────┘

1. CLIENT INITIATES AUTHORIZATION
   ┌──────────────┐
   │ OAuth Client │ (e.g., React App)
   └──────┬───────┘
          │
          │ User must be authenticated first!
          │ (Via login or webauthn - creates session)
          │
          │ Generate PKCE
          ├─ code_verifier = random(43-128 chars)
          ├─ code_challenge = SHA256(code_verifier) base64url
          └─ state = random secure string
          │
          │ Redirect user to:
          │ GET /api/oauth/authorize?
          │    client_id=my-app
          │    redirect_uri=http://localhost:3000/callback
          │    response_type=code
          │    scope=openid profile email
          │    state=random_state
          │    code_challenge=xxx_base64
          │    code_challenge_method=S256
          ↓
   ┌─────────────────────────────────────────┐
   │ IDP: Check Session Cookie               │
   │                                         │
   │ If NO session:                          │
   │ → Redirect to /login                    │
   │                                         │
   │ If session exists:                      │
   │ → Continue to authorize endpoint        │
   └──────┬────────────────────────────────────┘
          │
          ↓
   ┌─────────────────────────────────────────┐
   │ IDP AUTHORIZATION ENDPOINT              │
   │ GET /api/oauth/authorize                │
   │ [Authorize] - Requires session          │
   │                                         │
   │ 1. Validate user is authenticated       │
   │    (from session cookie)                │
   │ 2. Validate client_id exists            │
   │ 3. Validate redirect_uri matches        │
   │ 4. Validate response_type == "code"     │
   │ 5. Validate state present               │
   │ 6. Validate code_challenge:             │
   │    - Format: [A-Za-z0-9\-_]+            │
   │    - Length: 43-128 chars               │
   │ 7. Validate method == "S256"            │
   │ 8. Generate authorization code          │
   │ 9. Store AuthorizationCode record       │
   │ 10. Redirect back with code + state     │
   └────────┬─────────────────────────────────┘
            │
            │ CREATE AuthorizationCode:
            ├─ code: random_secure_token
            ├─ client_id: requested_client_id
            ├─ redirect_uri: requested_redirect_uri
            ├─ code_challenge: from request
            ├─ code_challenge_method: "S256"
            ├─ user_id: authenticated_user_id
            ├─ scope: request.scope
            ├─ expires_at: now + 5 minutes
            └─ used: false
            │
            │ 302 Redirect
            ↓
   ┌──────────────────────────────────────────┐
   │ Browser: Redirected back to app          │
   │ Location: redirect_uri?                  │
   │          code=AUTH_CODE&                 │
   │          state=SAME_STATE                │
   └──────┬───────────────────────────────────┘
          │
          │ User browser redirects
          ↓
   ┌──────────────┐
   │ OAuth Client │
   │ (Backend)    │
   └──────┬───────┘
          │ ✅ Got authorization code
          │ ✅ Verify state matches
          │
          │ POST /api/oauth/token
          │ {
          │   grant_type: "authorization_code"
          │   code: AUTH_CODE
          │   client_id: my-app
          │   redirect_uri: http://localhost:3000/callback
          │   code_verifier: ORIGINAL_VERIFIER
          │   scope: "openid profile email"
          │ }
          ↓
   ┌──────────────────────────────────────┐
   │ OAuthController.Token()              │
   │ [AllowAnonymous]                     │
   │                                      │
   │ 1. Validate grant_type == "auth_code"│
   │ 2. Find AuthorizationCode by code    │
   │ 3. Validate not expired/used         │
   │ 4. Validate client_id matches        │
   │ 5. Validate redirect_uri matches     │
   │ 6. Validate PKCE:                    │
   │    a. Compute: SHA256(code_verifier) │
   │    b. Compare with code_challenge    │
   │    c. Use constant-time compare      │
   │ 7. Check user exists & email verified│
   │ 8. Generate JWT + ID Token           │
   │ 9. Generate new refresh token        │
   │ 10. Mark auth code as used           │
   │ 11. Return tokens                    │
   └──────┬───────────────────────────────┘
          │
          │ ✅ Return to client:
          ↓
   ┌──────────────────────────────────────┐
   │ {                                    │
   │   "access_token": "eyJ...",          │
   │   "id_token": "eyJ...",              │
   │   "refresh_token": "base64",         │
   │   "token_type": "Bearer",            │
   │   "expires_in": 1800                 │
   │ }                                    │
   └──────────────────────────────────────┘

✅ OAUTH2 FLOW COMPLETE
   Client now has JWT tokens for API access
```

---

## 4. Token Refresh Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    TOKEN REFRESH FLOW                           │
└─────────────────────────────────────────────────────────────────┘

1. REFRESH TOKEN REQUEST
   ┌─────────┐
   │ Client  │
   └────┬────┘
        │ POST /api/token/refresh
        │ {
        │   refresh_token: "base64_token"
        │ }
        ↓
   ┌─────────────────────────────────────┐
   │ TokenController.Refresh()           │
   │ - Get client IP                     │
   │ - Validate refresh token present    │
   │ - Hash provided token               │
   │ - Find in DB by hash                │
   │ - Validate token not revoked        │
   │ - Validate token not expired        │
   │ - Check for reuse (breach detection)│
   └──────┬────────────────────────────────┘
          │
          │ IF TOKEN WAS REUSED:
          │ ├─ Revoke this token
          │ ├─ Revoke ALL user's tokens  (Session chain breach)
          │ └─ Return 401 Unauthorized
          │
          │ IF TOKEN IS VALID:
          ├─ Mark old token as used
          ├─ Mark old token as revoked
          ├─ Store revoking IP
          ├─ Generate NEW JWT
          ├─ Generate NEW refresh token
          ├─ Store link: old -> new
          ├─ Save new refresh token
          ↓
   ┌─────────────────────────────────────┐
   │ Database Updated:                   │
   │ Old RefreshToken:                   │
   │ {                                   │
   │   IsUsed: TRUE                      │
   │   IsRevoked: TRUE                   │
   │   RevokedByIp: client_ip            │
   │   ReplacedByToken: new_token_hash   │
   │ }                                   │
   │                                     │
   │ New RefreshToken:                   │
   │ {                                   │
   │   Token: new_token_hash             │
   │   JwtId: new_jti                    │
   │   CreatedAt: now                    │
   │   ExpiryDate: now + 7 days          │
   │   CreatedByIp: client_ip            │
   │   IsUsed: false                     │
   │   IsRevoked: false                  │
   │ }                                   │
   └──────┬─────────────────────────────┘
          │
          │ ✅ Return to client:
          ↓
   ┌──────────────────────────────────┐
   │ {                                │
   │   "AccessToken": "eyJ...",       │
   │   "RefreshToken": "base64"       │
   │   "TokenType": "Bearer"          │
   │ }                                │
   └──────────────────────────────────┘

✅ TOKEN REFRESH COMPLETE
```

---

## 5. TOTP (2FA) Setup & Login Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    TOTP SETUP FLOW                              │
└─────────────────────────────────────────────────────────────────┘

1. USER INITIATES MFA SETUP
   ┌──────────┐
   │ User     │ (Authenticated with JWT)
   └──────┬───┘
          │ POST /api/totp/setup-totp
          │ Authorization: Bearer JWT
          ↓
   ┌──────────────────────────────────────┐
   │ TotpController.SetupTotp()           │
   │ [Authorize] - User must be logged in │
   │                                      │
   │ 1. Extract userId from JWT           │
   │ 2. Find user in DB                   │
   │ 3. Check TOTP not already enabled    │
   │ 4. Generate TOTP secret (32 bytes)   │
   │ 5. Generate backup codes (10 x 12)   │
   │ 6. Hash each backup code (Argon2id)  │
   │ 7. Store secret & hashed codes       │
   │ 8. Return ONLY secret (not codes!)   │
   └──────┬────────────────────────────────┘
          │
          ├─ Store: User.TotpSecret
          ├─ Store: User.IsTotpEnabled = true
          ├─ Store: User.BackupCodes = [hashed1, hashed2, ...]
          └─ Return:
          │
          │ { "secret": "JBSWY3..." }
          │
          │
          ↓
   ┌──────────────────────────────────────┐
   │ Return:                              │
   │ {                                    │
   │   "secret": "JBSWY3...",             │
   │   "qrCodeUrl": "otpauth://totp/...", │
   │   "backupCodes": [                   │
   │     "ABC123XYZ",                     │
   │     "DEF456UVW",                     │
   │     ... (10 total)                   │
   │   ]                                  │
   │ }                                    │
   └──────────────────────────────────────┘

2. LOGIN WITH TOTP ENABLED
   ┌──────────┐
   │ User     │
   └──────┬───┘
          │ POST /api/auth/login
          │ {
          │   email: "user@example.com"
          │   password: "Password123!"
          │   totpCode: "123456"  OR
          │   backupCode: "ABC123XYZ"
          │ }
          ↓
   ┌───────────────────────────────────┐
   │ AuthController.Login()            │
   │ (Follow standard login flow)      │
   │                                   │
   │ At MFA check:                     │
   │ - User.IsTotpEnabled == true      │
   │ - Require totpCode OR backupCode  │
   │                                   │
   │ TOTP VALIDATION:                  │
   │ ├─ Get User.TotpSecret            │
   │ ├─ Verify code with window:       │
   │ │  (previous 30s, future 30s)     │
   │ ├─ Constant-time compare          │
   │ └─ Return true/false              │
   │                                   │
   │ BACKUP CODE VALIDATION:           │
   │ ├─ Hash provided code             │
   │ ├─ Search in User.BackupCodes     │
   │ ├─ Constant-time compare          │
   │ ├─ If match: Remove from list     │
   │ └─ Return true/false              │
   │                                   │
   │ mfaVerified = true                │
   └───────┬───────────────────────────┘
           │
           │ Generate JWT with mfa=true claim
           │
           ↓
   ┌──────────────────────────────┐
   │ ✅ Login successful          │
   │ Return access + refresh      │
   │ (with mfa claim = "true")    │
   └──────────────────────────────┘

✅ 2FA FLOW COMPLETE
```

---

## 6. Password Reset Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                  PASSWORD RESET FLOW                             │
└──────────────────────────────────────────────────────────────────┘

1. USER REQUESTS PASSWORD RESET
   ┌──────────┐
   │ User     │
   └──────┬───┘
          │ POST /api/email/forgot-password
          │ { email: "user@example.com" }
          │
          │ (No timing info leaked - all requests take ~100ms)
          ↓
   ┌────────────────────────────────┐
   │ EmailController.ForgotPassword()│
   │ 1. Try to find user by email    │
   │ 2. If not found, still wait     │
   │    100ms and return OK          │
   │    (prevent user enumeration)   │
   │ 3. Generate reset token         │
   │ 4. Hash token (SHA256)          │
   │ 5. Store hashed + expiry        │
   │ 6. Send email with token link   │
   └────────┬──────────────────────┘
            │
            │ User.PasswordResetTokenHash = hash(token)
            │ User.PasswordResetTokenExpiry = now + 1h
            │
            │ Send email:
            │ https://idp.example.com/reset?
            │  token=TOKEN&
            │  userId=USER_ID
            ↓
   ┌────────────────────────────┐
   │ User receives email         │
   │ Clicks reset link           │
   └──────────┬──────────────────┘
              │
              │ POST /api/email/reset-password
              │ {
              │   userId: "...",
              │   token: "...",
              │   newPassword: "NewPassword123!"
              │ }
              ↓
   ┌──────────────────────────────┐
   │ EmailController.ResetPassword()
   │ 1. Find user by ID            │
   │ 2. Validate token not expired │
   │ 3. Hash provided token        │
   │ 4. Compare with stored hash   │
   │    (constant-time)            │
   │ 5. Validate new password      │
   │ 6. Hash new password          │
   │ 7. Update PasswordHash        │
   │ 8. Clear reset token fields   │
   │ 9. REVOKE ALL SESSIONS        │
   │    (Logout all devices)       │
   └────────┬──────────────────────┘
            │
            │ User.PasswordHash = new_hash
            │ User.PasswordResetTokenHash = ""
            │ User.PasswordResetTokenExpiry = null
            │
            │ Revoke all refresh tokens:
            │ RefreshToken.IsRevoked = true
            │ RefreshToken.IsUsed = true
            │ For all tokens with UserId = user.Id
            │
            ↓
   ┌──────────────────────────────┐
   │ ✅ Password reset complete   │
   │ User must login again         │
   │ All old sessions invalidated  │
   └──────────────────────────────┘

✅ PASSWORD RESET FLOW COMPLETE
```

---

## 7. Logout Flow

```
┌──────────────────────────────────────────────────────────────┐
│                      LOGOUT FLOW                             │
└──────────────────────────────────────────────────────────────┘

1. USER INITIATES LOGOUT
   ┌──────────┐
   │ User     │
   └──────┬───┘
          │ POST /api/auth/logout
          │ Authorization: Bearer JWT
          │ {
          │   refreshToken: "base64_token"
          │ }
          ↓
   ┌──────────────────────────────┐
   │ AuthController.Logout()      │
   │ [Authorize] - JWT required   │
   │                              │
   │ 1. Get client IP             │
   │ 2. Hash refresh token        │
   │ 3. Find token in DB          │
   │ 4. Mark as revoked           │
   │ 5. Mark as used              │
   │ 6. Store revoking IP         │
   │ 7. Also revoke JWT (JTI)     │
   └──────┬────────────────────────┘
          │
          │ RefreshToken.IsRevoked = true
          │ RefreshToken.IsUsed = true
          │ RefreshToken.RevokedByIp = client_ip
          │
          │ SecurityService.RevokeJtiAsync(jti)
          │
          │ Return: OK("Logged out")
          ↓
   ┌──────────────────────────────┐
   │ ✅ Logout complete           │
   │ Token invalidated            │
   │ User must login again        │
   └──────────────────────────────┘

✅ LOGOUT FLOW COMPLETE
```

---

## Security Properties Per Flow

| Flow | AuthN | AuthZ | PKCE | MFA | Token Rot | Reuse Det | 
|------|-------|-------|------|-----|----------|-----------|
| Login | ✅ Arg2id | N/A | N/A | ✅ | N/A | N/A |
| OAuth | ✅ JWT | ✅ Scope | ✅ | N/A | ✅ | N/A |
| Refresh | N/A | N/A | N/A | ✅ | ✅ | ✅ |
| Email Ver | ✅ Token | N/A | N/A | N/A | N/A | N/A |
| TOTP Setup | ✅ JWT | N/A | N/A | N/A | N/A | N/A |
| Reset Pass | ✅ Token | N/A | N/A | N/A | ✅ | N/A |
| Logout | ✅ JWT | N/A | N/A | N/A | N/A | N/A |

Legend:
- ✅ = Implemented correctly
- ⚠️ = Partially implemented
- 🔴 = Missing/Broken

---

## Rate Limiting Applied

```
Endpoint: /api/auth/login
Rate: 15 req/min

Endpoint: /api/auth/register
Rate: 15 req/min

Endpoint: /api/token/refresh
Rate: 15 req/min

Endpoint: /api/oauth/token
Rate: 15 req/min

Endpoint: /api/email/forgot-password
Rate: 15 req/min

Endpoint: All others
Rate: 15 req/min
```