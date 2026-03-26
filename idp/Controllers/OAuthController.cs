using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using idp.Data;
using idp.Models;
using idp.Services;
using idp.Controllers.Requests;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class OAuthController : Controller
{
    private readonly AppDbContext _context;
    private readonly TokenService _tokenService;

    public OAuthController(AppDbContext context, TokenService tokenService)
    {
        _context = context;
        _tokenService = tokenService;
    }

    [Authorize]
    [EnableRateLimiting("auth")]
    [HttpGet("authorize")]
    public async Task<IActionResult> Authorize([FromQuery] AuthorizeRequest request)
    {
        if (request.ResponseType != "code")
            return BadRequest("invalid_response_type");

        var client = await _context.Set<OAuthClient>()
            .FirstOrDefaultAsync(c => c.ClientId == request.ClientId);

        if (client == null)
            return BadRequest("invalid_client");

        if (!client.RedirectUris.Any(uri => uri.Equals(request.RedirectUri, StringComparison.Ordinal)))
            return BadRequest("invalid_redirect_uri");
        
        if (string.IsNullOrEmpty(request.State))
            return BadRequest("invalid_state");

        // enforce PKCE if required
        if (client.RequirePkce)
        {
            if (string.IsNullOrEmpty(request.CodeChallenge) ||
                request.CodeChallengeMethod != "S256")
            {
                return BadRequest("invalid_pkce");
            }
        }

        var code = Guid.NewGuid().ToString("N");
        
        var authCode = new AuthorizationCode
        {
            Code = code,
            ClientId = request.ClientId,
            RedirectUri = request.RedirectUri,
            CodeChallenge = request.CodeChallenge,
            CodeChallengeMethod = request.CodeChallengeMethod,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
            Used = false,
            UserId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ?? throw new Exception("User ID claim missing")
        };

        _context.AuthorizationCodes.Add(authCode);
        await _context.SaveChangesAsync();

        // redirect back with code + state
        var redirectUrl = $"{request.RedirectUri}?code={code}&state={request.State}";

        return Redirect(redirectUrl);
    }

    [Authorize(Policy = "SensitiveOperation")]
    [EnableRateLimiting("auth")]
    [HttpPost("token")]
    public async Task<IActionResult> Token([FromForm] TokenRequest request)
    {
        if (request.GrantType != "authorization_code")
            return BadRequest("unsupported_grant_type");

        var client = await _context.Set<OAuthClient>()
            .FirstOrDefaultAsync(c => c.ClientId == request.ClientId);

        if (client == null)
            return BadRequest("invalid_client");

        var authCode = await _context.AuthorizationCodes
            .FirstOrDefaultAsync(c => c.Code == request.Code);

        if (authCode == null ||
            authCode.ExpiresAt < DateTime.UtcNow ||
            authCode.RedirectUri != request.RedirectUri ||
            authCode.ClientId != request.ClientId)
            return BadRequest("invalid_grant");

        if (authCode.Used)
            return BadRequest("invalid_grant");

        // PKCE
        if (!string.IsNullOrEmpty(authCode.CodeChallenge))
        {
            if (string.IsNullOrEmpty(request.CodeVerifier))
                return BadRequest("invalid_grant");

            var hashed = Convert.ToBase64String(
                    SHA256.HashData(Encoding.ASCII.GetBytes(request.CodeVerifier)))
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            if (hashed != authCode.CodeChallenge)
                return BadRequest("invalid_grant");
        }

        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Username == authCode.UserId);

        if (user == null)
            return BadRequest("invalid_grant");

        authCode.Used = true;

        var accessToken = await _tokenService.GenerateJwtToken(user, true);
        var refreshTokenValue = TokenService.GenerateRefreshToken();

        var refreshToken = new RefreshToken
        {
            Token = _tokenService.HashToken(refreshTokenValue), // Store hashed version
            JwtId = Guid.NewGuid().ToString(),
            UserId = user.Username,
            ExpiryDate = DateTime.UtcNow.AddDays(7)
        };
        
        _context.Add(refreshToken);
        await _context.SaveChangesAsync();

        await _context.SaveChangesAsync();

        return Ok(new
        {
            access_token = accessToken,
            token_type = "Bearer",
            RefreshToken = refreshTokenValue,
            expires_in = 1800
        });
    }
}