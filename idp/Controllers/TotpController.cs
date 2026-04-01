using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using System.IdentityModel.Tokens.Jwt;
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
    
    public TotpController(AppDbContext context, ErrorService errorService, BackupCodeService backUpCodeService)
    {
        _context = context;
        _errorService = errorService;
        _backUpCodeService = backUpCodeService;
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
        
        if (user.IsTotpEnabled && !string.IsNullOrEmpty(user.TotpSecret))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);

        var secret = KeyGeneration.GenerateRandomKey(20);
        user.TotpSecret = Base32Encoding.ToString(secret);
        user.IsTotpEnabled = true;

        var plainCodes = _backUpCodeService.GenerateBackupCodes();
        user.BackupCodes = plainCodes.Select(code => _backUpCodeService.HashBackupCode(code)).ToList();

        await _context.SaveChangesAsync();

        var qrCodeUrl = $"otpauth://totp/Idp:{user.Username}?secret={user.TotpSecret}&issuer=Idp";

        return Ok(new { Secret = user.TotpSecret, QrCodeUrl = qrCodeUrl, BackupCodes = plainCodes });
    }
}