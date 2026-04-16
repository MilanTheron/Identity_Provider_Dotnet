using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using idp.Data;
using idp.Services;
using idp.Models.Errors;
using idp.Controllers.Requests.Email;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class EmailController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly ErrorService _errorService;
    private readonly ILogger<EmailController> _logger;
    private readonly SendEmailService _emailService;
    private readonly TokenService _tokenService;
    private readonly PasswordService _passwordService;

    public EmailController(AppDbContext context, ErrorService errorService, ILogger<EmailController> logger, SendEmailService emailService, TokenService tokenService, PasswordService passwordService)
    {
        _context = context;
        _errorService = errorService;
        _logger = logger;
        _emailService = emailService;
        _tokenService = tokenService;
        _passwordService = passwordService;
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpGet("verify-email")]
    public async Task<IActionResult> VerifyEmail([FromQuery] string token, [FromQuery] string userId)
    {
        if (!Guid.TryParse(userId, out var guid))
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == guid);

        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        if (user.EmailVerified)
            return Ok("Already verified");

        if (user.EmailVerificationTokenExpiry == null || user.EmailVerificationTokenExpiry < DateTime.UtcNow)
            return _errorService.BadReq("token_expired");

        if (string.IsNullOrEmpty(user.EmailVerificationTokenHash) || string.IsNullOrEmpty(token))
            return _errorService.AuthError("invalid_token");
        
        var hashed = _tokenService.HashToken(token);

        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(user.EmailVerificationTokenHash),
                Convert.FromBase64String(hashed)))
            return _errorService.AuthError("invalid_token");

        user.EmailVerified = true;
        user.EmailVerificationTokenHash = null;
        user.EmailVerificationTokenExpiry = null;
        await _context.SaveChangesAsync();

        return Ok("Email verified");
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("resend-verification")]
    public async Task<IActionResult> ResendVerification([FromBody] ResendVerificationRequest request)
    {
        var user = await _context.Users.SingleOrDefaultAsync(u => u.Email == request.Email);
        if (user == null || user.EmailVerified)
        { 
            await Task.Delay(100);
            return Ok();
        }

        var rawToken = TokenService.GenerateSecureToken();
        user.EmailVerificationTokenHash = _tokenService.HashToken(rawToken);
        user.EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(24);
        await _context.SaveChangesAsync();

        var verifyUrl = $"{Request.Scheme}://{Request.Host}/api/email/verify-email?token={rawToken}&userId={user.Id}";
        await _emailService.SendEmail(user.Email, "Verify your email", $"Click to verify: <a href='{verifyUrl}'>link</a>");
        _logger.LogInformation("Verification email sent to {Email}", user.Email);
    
        return Ok();
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        var user = await _context.Users.SingleOrDefaultAsync(u => u.Email == request.Email);
        if (user == null)
        {
            await Task.Delay(100);
            return Ok();
        }

        var rawToken = TokenService.GenerateSecureToken();
        user.PasswordResetTokenHash = _tokenService.HashToken(rawToken);
        user.PasswordResetTokenExpiry = DateTime.UtcNow.AddHours(1);
        await _context.SaveChangesAsync();

        var resetUrl = $"{Request.Scheme}://{Request.Host}/api/email/reset-password?token={rawToken}&userId={user.Id}";
        await _emailService.SendEmail(user.Email, "Reset your password", $"Click here to reset your password: <a href='{resetUrl}'>link</a>");
        _logger.LogInformation("Password reset email sent to {Email}", user.Email);

        return Ok();
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        if (!Guid.TryParse(request.UserId, out var guid))
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == guid);
        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        if (user.PasswordResetTokenExpiry == null || user.PasswordResetTokenExpiry < DateTime.UtcNow)
            return _errorService.BadReq("token_expired");

        if (string.IsNullOrEmpty(user.PasswordResetTokenHash) || string.IsNullOrEmpty(request.Token))
            return _errorService.AuthError("invalid_token");
        
        if (string.IsNullOrEmpty(request.NewPassword))
            return _errorService.BadReq("password_required");

        var hashed = _tokenService.HashToken(request.Token);

        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(user.PasswordResetTokenHash),
                Convert.FromBase64String(hashed)))
            return _errorService.AuthError("invalid_token");

        if (await PasswordService.IsWeak(request.NewPassword))
            return BadRequest("Password too weak");

        user.PasswordHash = _passwordService.HashPassword(request.NewPassword);
        user.PasswordResetTokenHash = "";
        user.PasswordResetTokenExpiry = null;

        // revoke all sessions
        var tokens = await _context.RefreshTokens.Where(rt => rt.UserId == user.Id && !rt.IsRevoked).ToListAsync();
        foreach (var t in tokens)
        {
            t.IsRevoked = true;
            t.IsUsed = true;
        }

        await _context.SaveChangesAsync();
        return Ok("Password reset successfully");
    }
}