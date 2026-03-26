using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using idp.Services;
using idp.Data;
using idp.Models;
using System.Security.Cryptography;
using System.Text;

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
    
    [Authorize(Policy = "SensitiveOperation")]
    [EnableRateLimiting("auth")]
    [HttpPost("token/refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
            return BadRequest("Refresh token is required");
        
        var candidateTokens = await _context.Set<RefreshToken>()
            .Where(rt => !rt.IsRevoked && rt.ExpiryDate >= DateTime.UtcNow)
            .ToListAsync();
        
        RefreshToken? storedToken = null;
        var requestBytes = Encoding.UTF8.GetBytes(request.RefreshToken);

        // Constant-time comparison
        foreach (var token in candidateTokens)
        {
            var tokenBytes = Encoding.UTF8.GetBytes(token.Token);
            if (CryptographicOperations.FixedTimeEquals(tokenBytes, requestBytes))
            {
                storedToken = token;
                break;
            }
        }
        
        if (storedToken == null || storedToken.IsRevoked || storedToken.ExpiryDate < DateTime.UtcNow)
            return Unauthorized("Invalid refresh token");

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == storedToken.UserId);
        if (user == null)
            return BadRequest("Invalid username");

        // Revoke old token
        storedToken.IsRevoked = true;

        // Generate new tokens
        var newAccessToken = _tokenService.GenerateJwtToken(user, true);
        var newRefreshTokenValue = TokenService.GenerateRefreshToken();

        var newRefreshToken = new RefreshToken
        {
            Token = _tokenService.HashToken(newRefreshTokenValue), // Store hashed version
            JwtId = Guid.NewGuid().ToString(),
            UserId = user.Username,
            ExpiryDate = DateTime.UtcNow.AddDays(7)
        };
        _context.Add(newRefreshToken);
        await _context.SaveChangesAsync();

        return Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshTokenValue });
    }
}