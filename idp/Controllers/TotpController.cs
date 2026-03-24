using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using idp.Controllers.Requests;
using idp.Services;
using idp.Data;
using OtpNet;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TotpController : ControllerBase
{
    private readonly BackupCodeService _backupCodeService;
    private readonly AppDbContext _context;
    
    public TotpController(AppDbContext context, BackupCodeService backupCodeService)
    {
        _context = context;
        _backupCodeService = backupCodeService;
    }
    
    [HttpPost("setup-totp")]
    public async Task<IActionResult> SetupTotp([FromBody] SetupTotpRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
            return NotFound();

        var secret = KeyGeneration.GenerateRandomKey(20);
        user.TotpSecret = Base32Encoding.ToString(secret);
        user.IsTotpEnabled = true;

        // Generate backup codes
        var plainCodes = _backupCodeService.GenerateBackupCodes();
        user.BackupCodes = plainCodes.Select(code => _backupCodeService.HashBackupCode(code)).ToList(); // Save codes(hash) into user

        await _context.SaveChangesAsync();

        var qrCodeUrl = $"otpauth://totp/Idp:{user.Username}?secret={user.TotpSecret}&issuer=Idp";

        return Ok(new { Secret = user.TotpSecret, QrCodeUrl = qrCodeUrl, BackupCodes = plainCodes });
    }
}