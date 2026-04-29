using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using idp.Models.Errors;
using idp.Services;
using idp.Data;
using idp.Models;
using idp.Controllers.Requests;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TokenController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly TokenService _tokenService;
    private readonly ErrorService _errorService;
    
    public TokenController(AppDbContext context, TokenService tokenService, ErrorService errorService)
    {
        _context = context;
        _tokenService = tokenService;
        _errorService = errorService;
    }
    
    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("token/refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (clientIp == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);
        
        if (string.IsNullOrEmpty(request.RefreshToken))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);

        await using var transaction = await _context.Database.BeginTransactionAsync();
        
        var requestHash = _tokenService.HashToken(request.RefreshToken);
        var storedToken = await _context.RefreshTokens
            .SingleOrDefaultAsync(rt => rt.Token == requestHash);

        if (storedToken == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        if (storedToken.IsRevoked)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        if (storedToken.IsUsed) // REUSE DETECTED, revoking all user sessions
        {
            var userTokens = _context.RefreshTokens
                .Where(rt => rt.UserId == storedToken.UserId && !rt.IsRevoked);

            await userTokens.ForEachAsync(t => t.IsRevoked = true);
            await _context.SaveChangesAsync();
            await transaction.CommitAsync();
            
            return _errorService.AuthError(ErrorCodes.Unauthorized);
        }

        if (storedToken.ExpiryDate < DateTime.UtcNow)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var user = await _context.Users
            .SingleOrDefaultAsync(u => u.Id == storedToken.UserId);

        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        // Revoke old token
        storedToken.IsUsed = true;
        storedToken.IsRevoked = true;
        storedToken.RevokedByIp = clientIp;

        // Generate new tokens
        var (newAccessToken, newJti) = await _tokenService.GenerateJwtToken(user, storedToken.MfaVerified, storedToken.Scope, storedToken.ClientId);
        var newRefreshTokenValue = TokenService.GenerateSecureToken();
        var newRefreshTokenHash = _tokenService.HashToken(newRefreshTokenValue);
        storedToken.ReplacedByToken = newRefreshTokenHash;

        var newRefreshToken = new RefreshToken
        {
            Token = newRefreshTokenHash,
            JwtId = newJti,
            UserId = user.Id,
            ExpiryDate = DateTime.UtcNow.AddDays(7),
            CreatedAt = DateTime.UtcNow,
            CreatedByIp = clientIp,
            MfaVerified = storedToken.MfaVerified,
            IsUsed = false,
            IsRevoked = false,
            Scope = storedToken.Scope,
            ClientId = storedToken.ClientId
        };
        
        _context.Add(newRefreshToken);
        await _context.SaveChangesAsync();
        await transaction.CommitAsync();

        return Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshTokenValue });
    }
}