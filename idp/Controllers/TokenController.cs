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

        var requestHash = TokenService.HashToken(request.RefreshToken);

        var storedToken = await _context.RefreshTokens
            .FirstOrDefaultAsync(rt =>
                rt.Token == requestHash &&
                !rt.IsRevoked &&
                rt.ExpiryDate >= DateTime.UtcNow);

        if (storedToken == null)
            return Unauthorized("Invalid refresh token");

        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id.ToString() == storedToken.UserId);

        if (user == null)
            return NotFound();

        // Revoke old token
        storedToken.IsRevoked = true;

        // Generate new tokens
        var (newAccessToken, newJti) = await _tokenService.GenerateJwtToken(user, true);
        var newRefreshTokenValue = TokenService.GenerateRefreshToken();

        var newRefreshToken = new RefreshToken
        {
            Token = TokenService.HashToken(newRefreshTokenValue),
            JwtId = newJti,
            UserId = user.Id.ToString(),
            ExpiryDate = DateTime.UtcNow.AddDays(7)
        };

        _context.Add(newRefreshToken);
        await _context.SaveChangesAsync();

        return Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshTokenValue });
    }
}