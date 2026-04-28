using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
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
    private readonly ErrorService _errorService;
    private readonly TokenService _tokenService;
    
    public AuthController(
        AppDbContext context,
        ErrorService errorService,
        TokenService tokenService)
    {
        _context = context;
        _errorService = errorService;
        _tokenService = tokenService;
    }

    [Authorize]
    [EnableRateLimiting("auth")]
    [HttpPost("logout/session")]
    public async Task<IActionResult> LogoutSession()
    {
        await HttpContext.SignOutAsync("AuthScheme");
        return Ok(new { message = "logged out" });
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
        
        var requestHash = _tokenService.HashToken(request.RefreshToken);
        var storedToken = await _context.RefreshTokens
            .SingleOrDefaultAsync(rt => rt.Token == requestHash);

        if (storedToken == null)
            return _errorService.ConflictError(ErrorCodes.Conflict);
        
        storedToken.IsRevoked = true;
        storedToken.IsUsed = true;
        storedToken.RevokedByIp = clientIp;
        await _context.SaveChangesAsync();

        return Ok("Logged out");
    }
}