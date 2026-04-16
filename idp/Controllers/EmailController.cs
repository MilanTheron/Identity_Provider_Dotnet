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
    private readonly TokenService _tokenService;

    public EmailController(AppDbContext context, ErrorService errorService, TokenService tokenService)
    {
        _context = context;
        _errorService = errorService;
        _tokenService = tokenService;
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
}