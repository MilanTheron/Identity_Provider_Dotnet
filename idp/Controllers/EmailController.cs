using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using idp.Data;
using idp.Services;
using idp.Models.Errors;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class EmailController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly ErrorService _errorService;
    private readonly ILogger<EmailController> _logger;

    public EmailController(AppDbContext context, ErrorService errorService, ILogger<EmailController> logger)
    {
        _context = context;
        _errorService = errorService;
        _logger = logger;
    }
    
    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpGet("verify-email")]
    public async Task<IActionResult> VerifyEmail(string token, string userId)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id.ToString() == userId);

        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        if (user.EmailVerified)
            return Ok("Already verified");

        if (user.EmailVerificationTokenExpiry == null || user.EmailVerificationTokenExpiry < DateTime.UtcNow)
            return _errorService.BadReq("token_expired");
        
        if (string.IsNullOrEmpty(user.EmailVerificationTokenHash))
            return _errorService.AuthError("invalid_token");

        var hashed = TokenService.HashToken(token);

        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(user.EmailVerificationTokenHash),
                Convert.FromBase64String(hashed)))
        {
            return _errorService.AuthError("invalid_token");
        }

        user.EmailVerified = true;
        user.EmailVerificationTokenHash = null;
        user.EmailVerificationTokenExpiry = null;

        await _context.SaveChangesAsync();

        return Ok("Email verified");
    }
    
    [HttpPost("resend-verification")]
    public async Task<IActionResult> Resend(string email)
    {
        var user = await _context.Users.SingleOrDefaultAsync(u => u.Email == email);
        if (user == null) return Ok();

        if (user.EmailVerified) return Ok();

        var rawToken = TokenService.GenerateSecureToken();
        user.EmailVerificationTokenHash = TokenService.HashToken(rawToken);
        user.EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(24);

        await _context.SaveChangesAsync();

        // send email again
        _logger.LogInformation("Verify link: https://localhost:5001/api/email/verify-email?token={token}&userId={user.Id}", rawToken);

        return Ok();
    }
}