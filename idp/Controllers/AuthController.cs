using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using System.IdentityModel.Tokens.Jwt;
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

    public AuthController(AppDbContext context, TokenService tokenService, ErrorService errorService)
    {
        _context = context;
        _tokenService = tokenService;
        _errorService = errorService;
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        
        if (await PasswordService.IsWeak(request.Password))
            return BadRequest(@"Password is too weak, need: One maj letter, One min letter, One number, One special character([@$!%*?&^#()[\\]{}|\\\\/\\-+_.:;=,~`]), Min 12 chars");

        var user = new User
        {
            Username = request.Username,
            PasswordHash = PasswordService.HashPassword(request.Password),
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
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        if (string.IsNullOrEmpty(request.Scope))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);

        // Verify password
        if (!PasswordService.VerifyPassword(request.Password, user.PasswordHash))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);

        // Password correct, now check MFA if enabled
        var mfaVerified = false;

        if (user.IsTotpEnabled)
        {
            if (string.IsNullOrEmpty(request.TotpCode) && string.IsNullOrEmpty(request.BackupCode))
                return _errorService.AuthError(ErrorCodes.MfaRequired);
            
            if (!ValidateMfa(request, user))
                return _errorService.BadReq(ErrorCodes.MfaRequired);

            mfaVerified = true;
        }

        // Generate tokens
        var (accessToken, jti) = await _tokenService.GenerateJwtToken(user, mfaVerified);
        var refreshTokenValue = TokenService.GenerateRefreshToken();
        var refreshTokenHash = TokenService.HashToken(refreshTokenValue);

        var refreshToken = new RefreshToken
        {
            Token = refreshTokenHash,
            JwtId = jti,
            Scope = request.Scope,
            UserId = user.Id.ToString(),

            ExpiryDate = DateTime.UtcNow.AddDays(7),

            CreatedAt = DateTime.UtcNow,
            CreatedByIp = clientIp,

            MfaVerified = mfaVerified,
            IsUsed = false,
            IsRevoked = false,
            ReplacedByToken = null
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
            .FirstOrDefaultAsync(rt => rt.Token == requestHash);

        if (storedToken == null)
            return _errorService.ConflictError(ErrorCodes.Conflict);
        
        storedToken.IsRevoked = true;
        storedToken.IsUsed = true;
        storedToken.RevokedByIp = clientIp;
        await _context.SaveChangesAsync();

        return Ok("Logged out");
    }

    [EnableRateLimiting("auth")]
    [Authorize(Policy = "SensitiveOperation")]
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (clientIp == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);
        
        var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(userId))
            return _errorService.AuthError(ErrorCodes.Unauthorized);
        
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id.ToString() == userId);
        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        if (!PasswordService.VerifyPassword(request.OldPassword, user.PasswordHash))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        
        if (request.NewPassword == request.OldPassword)
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        
        if (await PasswordService.IsWeak(request.NewPassword))
            return BadRequest(@"Password is too weak, need: One maj letter, One min letter, One number, One special character([@$!%*?&^#()[\\]{}|\\\\/\\-+_.:;=,~`]), Min 12 chars");

        var transaction = await _context.Database.BeginTransactionAsync();

        user.PasswordHash = PasswordService.HashPassword(request.NewPassword);

        // Revoke tokens
        var tokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == user.Id.ToString() && !rt.IsRevoked)
            .ToListAsync();
        
        tokens.ForEach(t =>
        {
            t.IsRevoked = true;
            t.IsUsed = true;
            t.RevokedByIp = clientIp;
        });

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