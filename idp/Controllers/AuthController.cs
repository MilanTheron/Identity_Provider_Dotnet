using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
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
    private readonly ErrorService _errorService;
    private readonly PasswordService _passwordService;
    private readonly BackupCodeService _backupCodeService;
    private readonly SendEmailService _emailService;
    private readonly TokenService _tokenService;
    private readonly LoginDelayService _delayService;
    private readonly ILogger<AuthController> _logger;
    
    public AuthController(
        AppDbContext context,
        ErrorService errorService,
        PasswordService passwordService,
        BackupCodeService backupCodeService,
        SendEmailService emailService,
        TokenService tokenService,
        LoginDelayService delayService,
        ILogger<AuthController> logger)
    {
        _context = context;
        _errorService = errorService;
        _passwordService = passwordService;
        _backupCodeService = backupCodeService;
        _emailService = emailService;
        _tokenService = tokenService;
        _delayService = delayService;
        _logger = logger;
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        _logger.LogInformation("Email: {Email}, Password: {Password}", request.Email, request.Password);
        
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
        
        var user = new User
        {
            Device = device,
            Email = request.Email,
            PasswordHash = _passwordService.HashPassword(request.Password),
            EmailVerified = false,
            Credentials = new List<WebAuthnCredential>(),
            BackupCodes = new List<string>()
        };
    
        var rawToken = TokenService.GenerateSecureToken();
        user.EmailVerificationTokenHash = _tokenService.HashToken(rawToken);
        user.EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(24);
        
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        
        var verifyUrl =
            $"{Request.Scheme}://{Request.Host}/api/email/verify-email" +
            $"?token={Uri.EscapeDataString(rawToken)}&userId={user.Id}";
        _logger.LogInformation("Verify URL: {Url}", verifyUrl);
        
        try
        {
            await _emailService.SendEmail(
                user.Email,
                "Verify your email",
                verifyUrl);
            _logger.LogInformation("Verification email sent to {Email}", user.Email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send verification email to {Email}", user.Email);
        }

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

        var email = request.Email?.Trim().ToLowerInvariant() ?? "invalid";
        var ua = HttpContext.Request.Headers.UserAgent.ToString();
        var key = $"{clientIp}:{email}:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ua)))}";

        var user = await _context.Users
            .SingleOrDefaultAsync(u => u.Email == email);

        var password = request.Password ?? "Fake";

        if (user == null)
        {
            _delayService.RegisterFailure(key);
            await _delayService.ApplyDelayAsync(key);
            return _errorService.AuthError(ErrorCodes.InvalidCredentials);
        }

        if (!_passwordService.VerifyPassword(password, user.PasswordHash))
        {
            _delayService.RegisterFailure(key);
            await _delayService.ApplyDelayAsync(key);
            return _errorService.AuthError(ErrorCodes.InvalidCredentials);
        }

        // Reset delay on correct password
        _delayService.Reset(key);

        // ---- MFA ----
        var mfaVerified = false;

        if (user.IsTotpEnabled)
        {
            if (string.IsNullOrEmpty(request.TotpCode) &&
                string.IsNullOrEmpty(request.BackupCode) &&
                string.IsNullOrEmpty(request.TotpFallbackToken))
            {
                _delayService.RegisterFailure(key);
                await _delayService.ApplyDelayAsync(key);
                return _errorService.AuthError(ErrorCodes.MfaRequired);
            }

            if (!ValidateMfa(request, user))
            {
                _delayService.RegisterFailure(key);
                await _delayService.ApplyDelayAsync(key);
                return _errorService.AuthError(ErrorCodes.MfaRequired);
            }

            mfaVerified = true;
        }

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim("amr", "pwd"),
            new Claim("mfa", mfaVerified ? "true" : "false")
        };

        var identity = new ClaimsIdentity(claims, "AuthScheme");
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync("AuthScheme", principal);

        return Ok(new { message = "authenticated" });
    }

    [Authorize]
    [EnableRateLimiting("auth")]
    [HttpPost("logout/session")]
    public async Task<IActionResult> LogoutSession()
    {
        await HttpContext.SignOutAsync("AuthScheme");
        return Ok(new { message = "logged out" });
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
        
        var requestHash = _tokenService.HashToken(request.RefreshToken);
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
        int methodsUsed = 0;

        if (!string.IsNullOrWhiteSpace(request.TotpCode)) methodsUsed++;
        if (!string.IsNullOrWhiteSpace(request.BackupCode)) methodsUsed++;
        if (!string.IsNullOrWhiteSpace(request.TotpFallbackToken)) methodsUsed++;

        if (methodsUsed > 1)
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

            var hashed = _tokenService.HashToken(request.TotpFallbackToken);
            
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
            ));

        if (match == null)
            return false;

        user.BackupCodes.Remove(match);
        return true;
    }
}