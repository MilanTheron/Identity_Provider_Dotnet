using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
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
    private readonly BackupCodeService _backupCodeService;
    private readonly SecurityService _securityService;

    public AuthController(AppDbContext context, PasswordService passwordService, TokenService tokenService, BackupCodeService backupCodeService, SecurityService securityService)
    {
        _context = context;
        _passwordService = passwordService;
        _tokenService = tokenService;
        _backupCodeService = backupCodeService;
        _securityService = securityService;
    }

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
    
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (clientIp == null)
            return StatusCode(StatusCodes.Status500InternalServerError, "Unable to determine client IP");

        if (!_securityService.CanAttemptLogin(clientIp, out var waitTime))
            return StatusCode(StatusCodes.Status429TooManyRequests, $"Please wait {waitTime?.TotalSeconds:F0} seconds before trying again.");

        // Rate limiting check
        if (_securityService.IsRateLimited(clientIp))
            return StatusCode(StatusCodes.Status429TooManyRequests, "Too many login attempts. Please try again later.");

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
        {
            _securityService.RecordFailedAttempt(clientIp);
            return Unauthorized("Invalid username or password");
        }

        // Check account lockout
        if (user.LockoutEnd.HasValue && user.LockoutEnd > DateTime.UtcNow)
            return Unauthorized("Account locked due to too many failed attempts");

        // Verify password
        if (!_passwordService.VerifyPassword(request.Password, user.PasswordHash))
            return await FailLogin(user, clientIp, "Invalid username or password");

        // Password correct, now check MFA if enabled
        if (user.IsTotpEnabled && !ValidateMFA(request, user))
            return await FailLogin(user, clientIp, "Invalid MFA code");

        // Reset failed attempts and lockout on successful login
        user.FailedLoginAttempts = 0;
        user.LockoutEnd = null;
        await _context.SaveChangesAsync();

        // Generate tokens
        var accessToken = _tokenService.GenerateJwtToken(user);
        var refreshTokenValue = _tokenService.GenerateRefreshToken();

        var refreshToken = new RefreshToken
        {
            Token = _tokenService.HashToken(refreshTokenValue), // Store hashed version
            JwtId = Guid.NewGuid().ToString(),
            UserId = user.Username,
            ExpiryDate = DateTime.UtcNow.AddDays(7)
        };
        
        _context.Add(refreshToken);
        await _context.SaveChangesAsync();

        _securityService.ClearFailedAttempts(clientIp);

        return Ok(new { AccessToken = accessToken, RefreshToken = refreshTokenValue });
    }

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

    [Authorize]
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var username = User.Identity?.Name;
        if (string.IsNullOrEmpty(username))
            return Unauthorized();

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null)
            return NotFound();

        if (!_passwordService.VerifyPassword(request.OldPassword, user.PasswordHash))
            return BadRequest("Invalid old password");
        
        if (request.NewPassword == request.OldPassword)
            return BadRequest("New password cannot be the same as the old password");
        
        if (await _passwordService.IsWeak(request.NewPassword))
            return BadRequest("New password is too weak, need: One maj letter, One number, One special character, Min 8 chars");

        user.PasswordHash = _passwordService.HashPassword(request.NewPassword);

        // Revoke all refresh tokens for this user
        var refreshTokens = await _context.Set<RefreshToken>()
            .Where(rt => rt.UserId == username && !rt.IsRevoked)
            .ToListAsync();
        foreach (var token in refreshTokens)
        {
            token.IsRevoked = true;
        }

        await _context.SaveChangesAsync();

        return Ok("Password changed and all sessions revoked");
    }

    private bool ValidateMFA(LoginRequest request, User user)
    {
        // Try TOTP code first
        if (!string.IsNullOrEmpty(request.TotpCode))
        {
            var totp = new Totp(Base32Encoding.ToBytes(user.TotpSecret));

            // allow ±1 time step (default step = 30s → total ~±30s drift)
            var window = new VerificationWindow(previous: 1, future: 1);

            if (totp.VerifyTotp(request.TotpCode, out _, window))
                return true;
        }

        // Try backup code
        if (!string.IsNullOrEmpty(request.BackupCode) && user.BackupCodes != null)
        {
            var hashedBackup = _backupCodeService.HashBackupCode(request.BackupCode);
            if (user.BackupCodes.Contains(hashedBackup))
            {
                user.BackupCodes.Remove(hashedBackup);
                return true;
            }
        }

        return false;
    }
    
    private async Task<IActionResult> FailLogin(User user, string clientIp, string message)
    {
        await HandleFailedAttempt(user, clientIp);
        return Unauthorized(message);
    }
    
    private async Task<bool> HandleFailedAttempt(User user, string clientIp)
    {
        user.FailedLoginAttempts++;
        if (user.FailedLoginAttempts >= SecurityService.GetFailedAttemptsThreshold())
        {
            user.LockoutEnd = DateTime.UtcNow.Add(SecurityService.GetLockoutDuration());
        }
        await _context.SaveChangesAsync();
        _securityService.RecordFailedAttempt(clientIp);
        return false;
    }
}