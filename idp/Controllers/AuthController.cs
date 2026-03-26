using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using System.IdentityModel.Tokens.Jwt;
using OtpNet;
using idp.Data;
using idp.Models;
using idp.Services;
using idp.Controllers.Requests;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly PasswordService _passwordService;
    private readonly TokenService _tokenService;

    public AuthController(AppDbContext context, PasswordService passwordService, TokenService tokenService)
    {
        _context = context;
        _passwordService = passwordService;
        _tokenService = tokenService;
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            return BadRequest("User already exists");
        
        if (await _passwordService.IsWeak(request.Password))
            return BadRequest(@"Password is too weak, need: One maj letter, One min letter, One number, One special character([@$!%*?&^#()[\\]{}|\\\\/\\-+_.:;=,~`]), Min 12 chars");

        var user = new User
        {
            Username = request.Username,
            PasswordHash = _passwordService.HashPassword(request.Password),
            Email = request.Email
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();
    
        return Ok("User registered");
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (clientIp == null)
            return StatusCode(StatusCodes.Status500InternalServerError, "Unable to determine client IP");

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
        {
            return Unauthorized("Invalid username or password");
        }

        // Verify password
        if (!PasswordService.VerifyPassword(request.Password, user.PasswordHash))
            return BadRequest("Invalid username or password");

        // Password correct, now check MFA if enabled
        bool mfaVerified = false;

        if (user.IsTotpEnabled)
        {
            if (string.IsNullOrEmpty(request.TotpCode) && string.IsNullOrEmpty(request.BackupCode))
                return Unauthorized("MFA required");

            if (!ValidateMfa(request, user))
                return BadRequest("Invalid MFA code");

            mfaVerified = true;
        }
        else
            mfaVerified = true;

        await _context.SaveChangesAsync();

        // Generate tokens
        var accessToken = await _tokenService.GenerateJwtToken(user, mfaVerified);
        var refreshTokenValue = TokenService.GenerateRefreshToken();

        var refreshToken = new RefreshToken
        {
            Token = _tokenService.HashToken(refreshTokenValue), // Store hashed version
            JwtId = Guid.NewGuid().ToString(),
            UserId = user.Username,
            ExpiryDate = DateTime.UtcNow.AddDays(7)
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
        var requestHash = _tokenService.HashToken(request.RefreshToken);
        var storedToken = await _context.Set<RefreshToken>()
            .FirstOrDefaultAsync(rt => rt.Token == requestHash && !rt.IsRevoked && rt.ExpiryDate >= DateTime.UtcNow);

        if (storedToken != null && !storedToken.IsRevoked)
        {
            storedToken.IsRevoked = true;
            await _context.SaveChangesAsync();
        }

        return Ok("Logged out");
    }

    [EnableRateLimiting("auth")]
    [Authorize(Policy = "SensitiveOperation")]
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var username = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(username))
            return Unauthorized();

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null)
            return NotFound();

        if (!PasswordService.VerifyPassword(request.OldPassword, user.PasswordHash))
            return BadRequest("Invalid old password");
        
        if (request.NewPassword == request.OldPassword)
            return BadRequest("New password cannot be the same as the old password");
        
        if (await _passwordService.IsWeak(request.NewPassword))
            return BadRequest(@"Password is too weak, need: One maj letter, One min letter, One number, One special character([@$!%*?&^#()[\\]{}|\\\\/\\-+_.:;=,~`]), Min 12 chars");

        var transaction = await _context.Database.BeginTransactionAsync();

        user.PasswordHash = _passwordService.HashPassword(request.NewPassword);

        // Revoke tokens
        var tokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == username && !rt.IsRevoked)
            .ToListAsync();
        tokens.ForEach(t => t.IsRevoked = true);

        await _context.SaveChangesAsync();
        await transaction.CommitAsync();

        return Ok("Password changed and all sessions revoked");
    }

    private bool ValidateMfa(LoginRequest request, User user)
    {
        // TOTP
        if (!string.IsNullOrEmpty(request.TotpCode))
        {
            if (string.IsNullOrEmpty(user.TotpSecret))
                return false;

            var secretBytes = Base32Encoding.ToBytes(user.TotpSecret);
            var totp = new Totp(secretBytes);
            var window = new VerificationWindow(previous: 1, future: 1);

            if (totp.VerifyTotp(request.TotpCode.Trim(), out _, window))
                return true;
        }

        // Backup code
        if (!string.IsNullOrEmpty(request.BackupCode) && user.BackupCodes != null)
        {
            var hashedBackup = BackupCodeService.HashBackupCode(request.BackupCode.Trim());

            var match = user.BackupCodes.FirstOrDefault(c =>
                string.Equals(c, hashedBackup, StringComparison.Ordinal)
            );

            if (match != null)
            {
                user.BackupCodes.Remove(match);
                return true;
            }
        }

        return false;
    }
}