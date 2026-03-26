using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using idp.Controllers.Requests;
using idp.Services;
using idp.Data;
using OtpNet;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TotpController : ControllerBase
{
    private readonly AppDbContext _context;
    
    public TotpController(AppDbContext context)
    {
        _context = context;
    }
    
    [Authorize]
    [EnableRateLimiting("auth")]
    [HttpPost("setup-totp")]
    public async Task<IActionResult> SetupTotp([FromBody] SetupTotpRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
            return BadRequest("Invalid username");
        
        if (user.IsTotpEnabled && !string.IsNullOrEmpty(user.TotpSecret))
            return BadRequest("TOTP already enabled");

        var secret = KeyGeneration.GenerateRandomKey(20);
        user.TotpSecret = Base32Encoding.ToString(secret);
        user.IsTotpEnabled = true;

        var plainCodes = BackupCodeService.GenerateBackupCodes();
        user.BackupCodes = plainCodes.Select(code => BackupCodeService.HashBackupCode(code)).ToList();

        await _context.SaveChangesAsync();

        var qrCodeUrl = $"otpauth://totp/Idp:{user.Username}?secret={user.TotpSecret}&issuer=Idp";

        return Ok(new { Secret = user.TotpSecret, QrCodeUrl = qrCodeUrl, BackupCodes = plainCodes });
    }
}