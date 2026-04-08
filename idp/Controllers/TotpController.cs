using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using System.IdentityModel.Tokens.Jwt;
using idp.Controllers.Requests.Totp;
using idp.Models.Errors;
using idp.Services;
using idp.Data;
using OtpNet;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TotpController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly ErrorService _errorService;
    private readonly BackupCodeService _backUpCodeService;
    private readonly ILogger<TotpController> _logger;

    public TotpController(AppDbContext context, ErrorService errorService, BackupCodeService backUpCodeService, ILogger<TotpController> logger) 
    {
        _context = context;
        _errorService = errorService;
        _backUpCodeService = backUpCodeService;
        _logger = logger;
    }
    
    [Authorize]
    [EnableRateLimiting("auth")]
    [HttpPost("setup-totp")]
    public async Task<IActionResult> SetupTotp()
    {
        var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(userId))
            return _errorService.AuthError(ErrorCodes.Unauthorized);
        
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id.ToString() == userId);
        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);
        
        if (!string.IsNullOrEmpty(user.TotpSecret))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);

        var secret = KeyGeneration.GenerateRandomKey(20);
        user.TotpSecret = Base32Encoding.ToString(secret);
        user.IsTotpEnabled = false;
        
        var qrCodeUrl = GenerateTotpQrCode(user.Email, user.TotpSecret);

        await _context.SaveChangesAsync();
        
        return Ok(new TotpSetupResponse // dev only
        {
            Secret = user.TotpSecret,
            QrCodeUrl = qrCodeUrl
        }); 
        /*return Ok(new TotpSetupResponse
        {
            QrCodeUrl = qrCodeUrl
        });*/
    }
    
    [Authorize]
    [EnableRateLimiting("auth")]
    [HttpPost("verify-totp")]
    public async Task<IActionResult> VerifyTotp([FromBody] VerifyTotpRequest request)
    {
        var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(userId))
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id.ToString() == userId);
        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        if (string.IsNullOrEmpty(user.TotpSecret))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);

        if (string.IsNullOrWhiteSpace(request.Code))
            return _errorService.BadReq(ErrorCodes.InvalidCode);

        var secretBytes = Base32Encoding.ToBytes(user.TotpSecret);
        var totp = new Totp(secretBytes);
        var window = new VerificationWindow(previous: 1, future: 1);

        if (totp.VerifyTotp(request.Code.Trim(), out var step, window))
        {
            if (user.LastTotpStepUsed.HasValue &&
                user.LastTotpStepUsed.Value == step)
                return _errorService.BadReq(ErrorCodes.InvalidCode);

            user.LastTotpStepUsed = step;
        }
        else
            return _errorService.BadReq(ErrorCodes.InvalidCode);

        user.IsTotpEnabled = true;

        // invalidate old backup codes
        user.BackupCodes?.Clear();

        // generate new backup codes
        var plainCodes = _backUpCodeService.GenerateBackupCodes();

        user.BackupCodes = plainCodes
            .Select(code => _backUpCodeService.HashBackupCode(code))
            .ToList();

        _logger.LogInformation(
            "Generated {Count} backup codes for user {UserId}",
            plainCodes.Count,
            user.Id
        );

        await _context.SaveChangesAsync();

        return Ok(new
        {
            BackupCodes = plainCodes
        });
    }
    
    private string GenerateTotpQrCode(string email, string secret)
    {
        var encodedEmail = Uri.EscapeDataString(email);
        var provisioning = $"otpauth://totp/IDP:{encodedEmail}?secret={secret}&issuer=IDP";
        return provisioning;
    }
}