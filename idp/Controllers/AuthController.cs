using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Cryptography;
using OtpNet;
using idp.Data;
using idp.Models;
using idp.Services;
using idp.Models.Errors;
using idp.Controllers.Requests;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly TokenService _tokenService;
    private readonly ErrorService _errorService;
    private readonly PasswordService _passwordService;
    private readonly BackupCodeService _backupCodeService;
    private readonly SendEmailService _emailService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        AppDbContext context, 
        TokenService tokenService, 
        ErrorService errorService, 
        PasswordService passwordService, 
        BackupCodeService backupCodeService, 
        SendEmailService emailService,
        ILogger<AuthController> logger)
    {
        _context = context;
        _tokenService = tokenService;
        _errorService = errorService;
        _passwordService = passwordService;
        _backupCodeService = backupCodeService;
        _emailService = emailService;
        _logger = logger;
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        
        if (await _context.Users.AnyAsync(u => u.Email == request.Email))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
    
        if (await PasswordService.IsWeak(request.Password))
            return BadRequest(@"Password is too weak, need: One maj letter, One min letter, One number, One special character([@$!%*?&^#()[\\]{}|\\\\/\\-+_.:;=,~`]), Min 12 chars");

        var device = new Device
        {
            DeviceId = HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault() 
                       ?? HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknow",
            Location = null,
            LastUsed = DateTime.UtcNow
        };
        _context.Devices.Add(device);
        
        var user = new User
        {
            DeviceId = device.Id,
            Email = request.Email,
            PasswordHash = _passwordService.HashPassword(request.Password),
            EmailVerified = false,
            Credentials = new List<WebAuthnCredential>(),
            BackupCodes = new List<string>()
        };
    
        var rawToken = TokenService.GenerateSecureToken();
        user.EmailVerificationTokenHash = TokenService.HashToken(rawToken);
        user.EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(24);

        var verifyUrl = $"{Request.Scheme}://{Request.Host}/api/email/verify-email?token={rawToken}&userId={user.Id}";

        try
        {
            await _emailService.SendEmail(user.Email, "Verify your email", $"Click to verify: <a href='{verifyUrl}'>link</a>");
            _logger.LogInformation("Verification email sent to {Email}", user.Email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send verification email to {Email}", user.Email);
        }

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return Ok("User registered. If the email exists, a verification email has been sent.");
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (clientIp == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var user = await _context.Users
            .SingleOrDefaultAsync(u => u.Email == request.Email);
        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var scope = request.Scope ?? "openid profile email";

        if (!user.EmailVerified || string.IsNullOrEmpty(request.Password))
            return _errorService.AuthError(ErrorCodes.InvalidCredentials);
        
        if (!_passwordService.VerifyPassword(request.Password, user.PasswordHash))
            return _errorService.AuthError(ErrorCodes.InvalidCredentials);

        // Password correct, now check MFA if enabled
        var mfaVerified = false;

        if (user.IsTotpEnabled)
        {
            if (string.IsNullOrEmpty(request.TotpCode) && string.IsNullOrEmpty(request.BackupCode)
                                                       && string.IsNullOrEmpty(request.TotpFallbackToken))
                return _errorService.AuthError(ErrorCodes.MfaRequired);

            if (!ValidateMfa(request, user))
                return _errorService.BadReq(ErrorCodes.MfaRequired);

            mfaVerified = true;
        }

        // Generate tokens
        var (accessToken, jti) = await _tokenService.GenerateJwtToken(user, mfaVerified);
        var refreshTokenValue = TokenService.GenerateSecureToken();
        var refreshTokenHash = TokenService.HashToken(refreshTokenValue);

        var refreshToken = new RefreshToken
        {
            Token = refreshTokenHash,
            JwtId = jti,
            Scope = scope,
            UserId = user.Id.ToString(),

            ExpiryDate = DateTime.UtcNow.AddDays(7),

            CreatedAt = DateTime.UtcNow,
            CreatedByIp = clientIp,

            MfaVerified = mfaVerified,
            IsUsed = false,
            IsRevoked = false
        };
        
        _context.Add(refreshToken);
        await _context.SaveChangesAsync();

        return Ok(new { AccessToken = accessToken, RefreshToken = refreshTokenValue });
    }

    [Authorize]
    [EnableRateLimiting("auth")]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
    {
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (clientIp == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);
        
        if (string.IsNullOrEmpty(request.RefreshToken))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        
        var requestHash = TokenService.HashToken(request.RefreshToken);
        var storedToken = await _context.RefreshTokens
            .SingleOrDefaultAsync(rt => rt.Token == requestHash);

        if (storedToken == null)
            return _errorService.ConflictError(ErrorCodes.Conflict);
        
        storedToken.IsRevoked = true;
        storedToken.IsUsed = true;
        storedToken.RevokedByIp = clientIp;
        await _context.SaveChangesAsync();

        return Ok("Logged out");
    }

    private bool ValidateMfa(LoginRequest request, User user)
    {
        // prevent two being used at once
        if (!string.IsNullOrWhiteSpace(request.TotpCode) &&
            !string.IsNullOrWhiteSpace(request.BackupCode) &&
            !string.IsNullOrEmpty(request.TotpFallbackToken))
            return false;

        // ---- TOTP ----
        if (!string.IsNullOrWhiteSpace(request.TotpCode))
        {
            if (string.IsNullOrEmpty(user.TotpSecret))
                return false;

            try
            {
                var secretBytes = Base32Encoding.ToBytes(user.TotpSecret);
                var totp = new Totp(secretBytes);

                var window = new VerificationWindow(previous: 1, future: 1);

                var code = request.TotpCode.Trim();

                if (!totp.VerifyTotp(code, out var timeStepMatched, window))
                    return false;

                if (user.LastTotpStepUsed.HasValue &&
                    user.LastTotpStepUsed.Value == timeStepMatched)
                    return false;

                user.LastTotpStepUsed = timeStepMatched;
                return true;
            }
            catch
            {
                return false;
            }
        }
        
        // ---- TOTP Fallback ----
        if (!string.IsNullOrEmpty(request.TotpFallbackToken) && !string.IsNullOrEmpty(user.TotpFallbackTokenHash))
        {
            if (user.TotpFallbackTokenExpiry == null || user.TotpFallbackTokenExpiry < DateTime.UtcNow)
                return false;

            var hashed = TokenService.HashToken(request.TotpFallbackToken);
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromBase64String(user.TotpFallbackTokenHash),
                    Convert.FromBase64String(hashed)))
                return false;

            user.TotpFallbackTokenHash = null;
            user.TotpFallbackTokenExpiry = null;
            return true;
        }

        // ---- Backup code ----
        if (string.IsNullOrWhiteSpace(request.BackupCode) || user.BackupCodes == null)
            return false;

        if (user.BackupCodes.Count == 0)
            return false;

        var input = request.BackupCode.Trim();
        var hashedInput = _backupCodeService.HashBackupCode(input);

        var match = user.BackupCodes.FirstOrDefault(stored =>
            CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(stored),
                Convert.FromBase64String(hashedInput)
            )
        );

        if (match == null)
            return false;

        user.BackupCodes.Remove(match);
        return true;
    }
}