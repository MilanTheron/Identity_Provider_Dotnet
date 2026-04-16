using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using idp.Data;
using idp.Models;
using idp.Models.Errors;
using idp.Services;
using OtpNet;
using System.Text;
using System.Security.Claims;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;

namespace idp.Pages;
public class AuthModel : PageModel
{
    private readonly AppDbContext _context;
    private readonly PasswordService _passwordService;
    private readonly LoginDelayService _delayService;
    private readonly ErrorService _errorService;
    private readonly SendEmailService _emailService;
    private readonly TokenService _tokenService;
    private readonly BackupCodeService _backupCodeService;

    public AuthModel(
        AppDbContext context,
        PasswordService passwordService,
        LoginDelayService delayService,
        ErrorService errorService,
        SendEmailService emailService,
        TokenService tokenService,
        BackupCodeService backupCodeService)
    {
        _context = context;
        _passwordService = passwordService;
        _delayService = delayService;
        _errorService = errorService;
        _emailService = emailService;
        _tokenService = tokenService;
        _backupCodeService = backupCodeService;
    }

    [BindProperty]
    public string Email { get; set; }

    [BindProperty]
    public string Password { get; set; }
    
    [BindProperty]
    public string ConfirmPassword { get; set; }

    [BindProperty]
    public string? TotpCode { get; set; }

    [BindProperty]
    public string? BackupCode { get; set; }
    
    [BindProperty]
    public string? TotpFallbackToken { get; set; }

    [BindProperty(SupportsGet = true)]
    public string Mode { get; set; } = "login";
    
    [BindProperty]
    public string Action { get; set; }

    public string Message { get; set; }

    public async Task<IActionResult> OnPostAsync()
    {
        if (string.IsNullOrEmpty(Email))
        {
            Message = _errorService.Translate(ErrorCodes.InvalidRequest);
            return Page();
        }

        Email = Email.Trim().ToLowerInvariant();
        
        return Action switch
        {
            "resend" => await HandleResendVerification(),
            "register" => await HandleRegister(),
            "login" => await HandleLogin(),
            "forgot" => await HandleForgotPassword(),
            "reset" => await HandleResetPassword(),
            _ => Page()
        };
    }

    private async Task<IActionResult> HandleForgotPassword()
    {
        return Page();
    }
    
    private async Task<IActionResult> HandleResetPassword()
    {
        return Page();
    }

    private async Task<IActionResult> HandleResendVerification()
    {
        var user = await _context.Users.SingleOrDefaultAsync(u => u.Email == Email);
        if (user == null || user.EmailVerified)
        { 
            await Task.Delay(100);
            return Page();
        }

        var rawToken = TokenService.GenerateSecureToken();
        user.EmailVerificationTokenHash = _tokenService.HashToken(rawToken);
        user.EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(24);
        await _context.SaveChangesAsync();

        var verifyUrl =
            $"{Request.Scheme}://{Request.Host}/api/email/verify-email" +
            $"?token={Uri.EscapeDataString(rawToken)}&userId={user.Id}"; // change to use a built-in method instead of api
        await _emailService.SendEmail(user.Email, "Verify your email", verifyUrl);

        Message = "A new verification mail as been sent.";
        return Page();
    }
    
    private async Task<IActionResult> HandleRegister()
    {
        if (string.IsNullOrEmpty(Email) || string.IsNullOrEmpty(Password))
        {
            Message = _errorService.Translate(ErrorCodes.InvalidRequest);
            return Page();
        }
        
        if (await _context.Users.AnyAsync(u => u.Email == Email))
        {
            Message = _errorService.Translate(ErrorCodes.InvalidRequest);
            return Page();
        }
        
        if (await PasswordService.IsWeak(Password))
        {
            Message = _errorService.Translate(ErrorCodes.WeakPassword);
            return Page();
        }
        
        if (Password != ConfirmPassword)
        {
            Message = _errorService.Translate(ErrorCodes.PasswordsDoNotMatch);
            return Page();
        }
        
        var device = new Device
        {
            DeviceId = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            LastUsed = DateTime.UtcNow
        };
        
        var user = new User
        {
            Email = Email,
            PasswordHash = _passwordService.HashPassword(Password),
            EmailVerified = false,
            Device = device,
            BackupCodes = new List<string>(),
            Credentials = new List<WebAuthnCredential>()
        };
        
        var rawToken = TokenService.GenerateSecureToken();
        user.EmailVerificationTokenHash = _tokenService.HashToken(rawToken);
        user.EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(24);
        
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        
        try
        {
            var verifyUrl =
                $"{Request.Scheme}://{Request.Host}/api/email/verify-email" +
                $"?token={Uri.EscapeDataString(rawToken)}&userId={user.Id}"; // change to use a built-in method instead of api

            await _emailService.SendEmail(user.Email, "Verify your email", verifyUrl);
        }
        catch
        {
            // Intentionally silent (no leakage)
        }
        
        Message = "User registered. Verify email before login.";
        return Page();
    }

    private async Task<IActionResult> HandleLogin()
    {
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (clientIp == null)
            return Page();
        
        var email = Email.Trim().ToLowerInvariant();
        var ua = HttpContext.Request.Headers.UserAgent.ToString();
        var key = $"{clientIp}:{email}:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ua)))}";
        
        var user = await _context.Users
            .SingleOrDefaultAsync(u => u.Email == email);
        
        if (user == null)
        {
            _delayService.RegisterFailure(key);
            await _delayService.ApplyDelayAsync(key);
            Message = _errorService.Translate(ErrorCodes.InvalidCredentials);
            return Page();
        }
        
        if (!user.EmailVerified)
        {
            _delayService.RegisterFailure(key);
            await _delayService.ApplyDelayAsync(key);
            Message = _errorService.Translate(ErrorCodes.EmailNotVerified);
            return Page();
        }
        
        if (!_passwordService.VerifyPassword(Password, user.PasswordHash))
        {
            _delayService.RegisterFailure(key);
            await _delayService.ApplyDelayAsync(key);
            Message = _errorService.Translate(ErrorCodes.InvalidCredentials);
            return Page();
        }
        
        // Reset delay on correct password
        _delayService.Reset(key);
        
        // ---- MFA ----
        var mfaVerified = false;
        
        if (user.IsTotpEnabled)
        {
            if (string.IsNullOrWhiteSpace(TotpCode) &&
                string.IsNullOrEmpty(BackupCode) &&
                string.IsNullOrEmpty(TotpFallbackToken))
            {
                _delayService.RegisterFailure(key);
                await _delayService.ApplyDelayAsync(key);
                Message = _errorService.Translate(ErrorCodes.MfaRequired);
                return Page();
            }
            
            if (!ValidateMfa(user))
            {
                _delayService.RegisterFailure(key);
                await _delayService.ApplyDelayAsync(key);
                Message = _errorService.Translate(ErrorCodes.MfaRequired);
                return Page();
            }
            
            mfaVerified = true;
        }
        
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new("amr", "pwd"),
            new("mfa", mfaVerified ? "true" : "false")
        };
        
        var identity = new ClaimsIdentity(claims, "AuthScheme");
        var principal = new ClaimsPrincipal(identity);
        
        await HttpContext.SignInAsync("AuthScheme", principal);
        
        Message = "Login Successful";
        return Page();
    }

    private bool ValidateMfa(User user)
    {
        // prevent two being used at once
        int methodsUsed = 0;
        
        if (!string.IsNullOrWhiteSpace(TotpCode)) methodsUsed++;
        if (!string.IsNullOrWhiteSpace(BackupCode)) methodsUsed++;
        if (!string.IsNullOrWhiteSpace(TotpFallbackToken)) methodsUsed++;
        
        if (methodsUsed > 1)
            return false;
        
        // ---- TOTP ----
        if (!string.IsNullOrWhiteSpace(TotpCode))
        {
            if (string.IsNullOrEmpty(user.TotpSecret))
                return false;
            
            try
            {
                var secretBytes = Base32Encoding.ToBytes(user.TotpSecret);
                var totp = new Totp(secretBytes);
                
                var window = new VerificationWindow(previous: 1, future: 1);
                
                var code = TotpCode.Trim();
                
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
        if (!string.IsNullOrEmpty(TotpFallbackToken) && !string.IsNullOrEmpty(user.TotpFallbackTokenHash))
        {
            if (user.TotpFallbackTokenExpiry == null || user.TotpFallbackTokenExpiry < DateTime.UtcNow)
                return false;
            
            var hashed = _tokenService.HashToken(TotpFallbackToken);
            
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromBase64String(user.TotpFallbackTokenHash),
                    Convert.FromBase64String(hashed)))
                return false;

            user.TotpFallbackTokenHash = null;
            user.TotpFallbackTokenExpiry = null;
            return true;
        }
        
        // ---- Backup code ----
        if (string.IsNullOrWhiteSpace(BackupCode) || user.BackupCodes == null)
            return false;
        
        if (user.BackupCodes.Count == 0)
            return false;
        
        var input = BackupCode.Trim();
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

    private async Task FailDelay(string key)
    {
        _delayService.RegisterFailure(key);
        await _delayService.ApplyDelayAsync(key);
    }
}