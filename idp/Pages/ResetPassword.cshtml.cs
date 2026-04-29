using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using idp.Data;
using idp.Services;
using idp.Models.Errors;

namespace idp.Pages;
public class ResetPasswordModel : PageModel
{
    private readonly AppDbContext _context;
    private readonly PasswordService _passwordService;
    private readonly ErrorService _errorService;
    private readonly TokenService _tokenService;

    public ResetPasswordModel(
        AppDbContext context,
        PasswordService passwordService,
        ErrorService errorService,
        TokenService tokenService)
    {
        _context = context;
        _passwordService = passwordService;
        _errorService = errorService;
        _tokenService = tokenService;
    }
    
    [BindProperty(SupportsGet = true)]
    public string Token { get; set; }

    [BindProperty(SupportsGet = true)]
    public string UserId { get; set; }

    [BindProperty]
    public string NewPassword { get; set; }

    [BindProperty]
    public string ConfirmPassword { get; set; }

    public string? Message { get; set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (clientIp == null)
            return Page();
        
        var ua = HttpContext.Request.Headers.UserAgent.ToString();
        var key = $"{clientIp}:{UserId}:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ua)))}";
        
        await Task.Delay(100);
        
        if (!Guid.TryParse(UserId, out var guid))
            return await Fail(key, ErrorCodes.Unauthorized);
        
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == guid);
        if (user == null)
            return await Fail(key, ErrorCodes.Unauthorized);
        
        if (NewPassword != ConfirmPassword)
            return await Fail(key, ErrorCodes.PasswordsDoNotMatch);
        
        if (user.PasswordResetTokenExpiry == null || user.PasswordResetTokenExpiry < DateTime.UtcNow)
            return await Fail(key, "token_expired");

        if (string.IsNullOrEmpty(user.PasswordResetTokenHash) || string.IsNullOrEmpty(Token))
            return await Fail(key, "invalid_token");
        
        if (string.IsNullOrEmpty(NewPassword))
            return await Fail(key, "new_password_required");
        
        if (await PasswordService.IsWeak(NewPassword))
            return await Fail(key, ErrorCodes.WeakPassword);

        var hashed = _tokenService.HashToken(Token);

        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(user.PasswordResetTokenHash),
                Convert.FromBase64String(hashed)))
        {
            Message = _errorService.Translate("invalid token");
            return Page();
        }

        user.PasswordHash = _passwordService.HashPassword(NewPassword);
        user.PasswordResetTokenHash = null;
        user.PasswordResetTokenExpiry = null;

        // revoke all sessions
        var tokens = await _context.RefreshTokens.Where(rt => rt.UserId == user.Id && !rt.IsRevoked).ToListAsync();
        foreach (var t in tokens)
        {
            t.IsRevoked = true;
            t.IsUsed = true;
        }

        await _context.SaveChangesAsync();

        Message = "Password successfully reset. You can close this tab.";
        return Page();
    }
    
    private async Task<IActionResult> Fail(string key, string error)
    {
        Message = _errorService.Translate(error);
        return Page();
    }
}