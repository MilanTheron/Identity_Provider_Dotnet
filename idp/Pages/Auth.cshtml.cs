using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using idp.Data;
using idp.Models;
using idp.Services;
using idp.Models.Errors;
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
    private readonly AuthService _authService;

    public AuthModel(
        AppDbContext context,
        PasswordService passwordService,
        LoginDelayService delayService,
        ErrorService errorService,
        SendEmailService emailService,
        AuthService authService)
    {
        _context = context;
        _passwordService = passwordService;
        _delayService = delayService;
        _errorService = errorService;
        _emailService = emailService;
        _authService = authService;
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

    private string _key;
    
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public async Task<IActionResult> OnPostAsync()
    {
        if (string.IsNullOrEmpty(Email))
        {
            Message = _errorService.Translate(ErrorCodes.InvalidRequest);
            return Page();
        }
        
        Email = Email.Trim().ToLowerInvariant();
        
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (clientIp == null)
            return Page();
        
        var ua = HttpContext.Request.Headers.UserAgent.ToString();
        _key = $"{clientIp}:{Email}:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ua)))}";
        
        return Action switch
        {
            "resend" => await HandleResendVerification(),
            "register" => await HandleRegister(),
            "login" => await HandleLogin(),
            "forgot" => await HandleForgotPassword(),
            _ => Page()
        };
    }

    private async Task<IActionResult> HandleForgotPassword()
    {
        var user = await _context.Users
            .SingleOrDefaultAsync(u => u.Email == Email);

        await Task.Delay(100);

        if (user == null)
            return await Fail(_key, ErrorCodes.Unauthorized);

        var rawToken = TokenService.GenerateSecureToken();

        _authService.SetPasswordReset(user, rawToken);

        await _context.SaveChangesAsync();

        var resetUrl = $"{GetEmailBaseUrl()}/api/ResetPassword?token={Uri.EscapeDataString(rawToken)}&userId={user.Id}";

        await _emailService.SendEmail(user.Email, "Reset your password", resetUrl);

        Message = "If the email exists, a reset link has been sent.";
        return Page();
    }

    private async Task<IActionResult> HandleResendVerification()
    {
        var user = await _context.Users
            .SingleOrDefaultAsync(u => u.Email == Email);

        await Task.Delay(100);

        if (user == null || user.EmailVerified)
            return await Fail(_key, ErrorCodes.Unauthorized);

        var rawToken = TokenService.GenerateSecureToken();
        _authService.SetEmailVerification(user, rawToken);
        
        await _context.SaveChangesAsync();

        var verifyUrl = $"{GetEmailBaseUrl()}/api/email/verify-email?token={Uri.EscapeDataString(rawToken)}&userId={user.Id}";

        await _emailService.SendEmail(user.Email, "Verify your email", verifyUrl);

        Message = "A new verification mail as been sent.";
        return Page();
    }
    
    private async Task<IActionResult> HandleRegister()
    {
        if (string.IsNullOrEmpty(Email) || string.IsNullOrEmpty(Password))
            return await Fail(_key, ErrorCodes.InvalidRequest);
        
        if (await _context.Users.AnyAsync(u => u.Email == Email))
            return await Fail(_key, ErrorCodes.InvalidRequest);
        
        if (await PasswordService.IsWeak(Password))
            return await Fail(_key, ErrorCodes.WeakPassword);
        
        if (Password != ConfirmPassword)
            return await Fail(_key, ErrorCodes.PasswordsDoNotMatch);
        
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
        _authService.SetEmailVerification(user, rawToken);
        
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        
        try
        {
            var verifyUrl = $"{GetEmailBaseUrl()}/api/email/verify-email?token={Uri.EscapeDataString(rawToken)}&userId={user.Id}";

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
        if (string.IsNullOrEmpty(Email) || string.IsNullOrEmpty(Password))
            return await Fail(_key, ErrorCodes.InvalidRequest);
    
        var user = await _context.Users
            .SingleOrDefaultAsync(u => u.Email == Email);
    
        if (user == null)
            return await Fail(_key, ErrorCodes.InvalidCredentials);

        if (!user.EmailVerified)
            return await Fail(_key, ErrorCodes.EmailNotVerified);
    
        if (!_passwordService.VerifyPassword(Password, user.PasswordHash))
            return await Fail(_key, ErrorCodes.InvalidCredentials);

        // Reset delay on correct password
        _delayService.Reset(_key);
        
        // ---- MFA ----
        var mfaVerified = false;
        
        if (user.IsTotpEnabled)
        {
            if (string.IsNullOrWhiteSpace(TotpCode) &&
                string.IsNullOrEmpty(BackupCode) &&
                string.IsNullOrEmpty(TotpFallbackToken))
                return await Fail(_key, ErrorCodes.MfaRequired);
            
            if (!_authService.ValidateMfa(user, TotpCode, BackupCode, TotpFallbackToken))
                return await Fail(_key, ErrorCodes.MfaRequired);
            
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
        if (!string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl))
        {
            return Redirect(ReturnUrl);
        }
        return Page();
    }
    
    private string GetEmailBaseUrl()
    {
        var scheme = Request.Scheme;
        var host = Request.Host.Host;
    
        var port = Request.Host.Port;
        if (port.HasValue && port.Value != 80 && port.Value != 443)
        {
            return $"{scheme}://{host}:{port}";
        }
    
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) && !port.HasValue)
            return $"{scheme}://{host}:5000";
    
        return $"{scheme}://{host}";
    }
    
    private async Task<IActionResult> Fail(string key, string error)
    {
        var err = await _authService.FailureAsync(key, error);
        Message = _errorService.Translate(err);
        return Page();
    }
}