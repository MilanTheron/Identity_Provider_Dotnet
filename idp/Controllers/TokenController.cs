using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using idp.Services;
using idp.Data;
using idp.Models;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TokenController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly TokenService _tokenService;
    
    public TokenController(AppDbContext context, TokenService tokenService)
    {
        _context = context;
        _tokenService = tokenService;
    }
    
    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("token/refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
            return BadRequest("Refresh token is required");

        await using var transaction = await _context.Database.BeginTransactionAsync();
        
        var requestHash = TokenService.HashToken(request.RefreshToken);
        var storedToken = await _context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == requestHash);

        if (storedToken == null)
            return Unauthorized("Invalid refresh token");

        if (storedToken.IsRevoked)
            return Unauthorized("Token revoked");

        if (storedToken.IsUsed) // REUSE DETECTED, revoking all user sessions
        {
            var userTokens = _context.RefreshTokens
                .Where(rt => rt.UserId == storedToken.UserId && !rt.IsRevoked);

            await userTokens.ForEachAsync(t => t.IsRevoked = true);
            await _context.SaveChangesAsync();
            await transaction.CommitAsync();
            
            return Unauthorized("Token reuse detected");
        }

        if (storedToken.ExpiryDate < DateTime.UtcNow)
            return Unauthorized("Token expired");

        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id.ToString() == storedToken.UserId);

        if (user == null)
            return NotFound();

        // Revoke old token
        storedToken.IsUsed = true;
        storedToken.IsRevoked = true;
        storedToken.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString();

        // Generate new tokens
        var (newAccessToken, newJti) = await _tokenService.GenerateJwtToken(user, storedToken.MfaVerified);
        var newRefreshTokenValue = TokenService.GenerateRefreshToken();
        var newRefreshTokenHash = TokenService.HashToken(newRefreshTokenValue);
        storedToken.ReplacedByToken = newRefreshTokenHash;

        var newRefreshToken = new RefreshToken
        {
            Token = newRefreshTokenHash,
            JwtId = newJti,
            UserId = user.Id.ToString(),

            ExpiryDate = DateTime.UtcNow.AddDays(7),

            CreatedAt = DateTime.UtcNow,
            CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString(),

            MfaVerified = storedToken.MfaVerified,
            IsUsed = false,
            IsRevoked = false
        };
        
        _context.Add(newRefreshToken);
        await _context.SaveChangesAsync();
        await transaction.CommitAsync();

        return Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshTokenValue });
    }
}