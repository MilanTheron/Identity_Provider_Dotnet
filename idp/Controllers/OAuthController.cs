using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Text.RegularExpressions;
using System.Text;
using idp.Data;
using idp.Models;
using idp.Services;
using idp.Models.Errors;
using idp.Controllers.Requests.OAuth;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class OAuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly TokenService _tokenService;
    private readonly ErrorService _errorService;

    public OAuthController(AppDbContext context, TokenService tokenService, ErrorService errorService)
    {
        _context = context;
        _tokenService = tokenService;
        _errorService = errorService;
    }

    [Authorize(Policy = "SensitiveOperation")]
    [EnableRateLimiting("auth")]
    [HttpGet("authorize")]
    public async Task<IActionResult> Authorize([FromQuery] AuthorizeRequest request)
    {
        if (request.ResponseType != "code")
            return BadRequest(new { error = "invalid_response_type" });

        var client = await _context.Set<OAuthClient>()
            .SingleOrDefaultAsync(c => c.ClientId == request.ClientId);

        if (client == null)
            return BadRequest(new { error = "invalid_client" });

        if (!client.RedirectUris.Any(uri => uri.Equals(request.RedirectUri, StringComparison.Ordinal)))
            return BadRequest(new { error = "invalid_redirect_uri" });

        if (string.IsNullOrWhiteSpace(request.State))
            return BadRequest(new { error = "invalid_state" });
        
        var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(userId))
            return BadRequest(new { error = "invalid_user_id" });

        if (string.IsNullOrEmpty(request.CodeChallenge) ||
            !Regex.IsMatch(request.CodeChallenge, @"^[A-Za-z0-9\-_]+$"))
            return BadRequest(new { error = "invalid_code_challenge" });

        if (string.IsNullOrEmpty(request.CodeChallenge) || request.CodeChallengeMethod != "S256")
            return BadRequest(new { error = "invalid_pkce" });

        var code = TokenService.GenerateSecureToken();

        var authCode = new AuthorizationCode
        {
            Code = code,
            ClientId = request.ClientId,
            RedirectUri = request.RedirectUri,
            CodeChallenge = request.CodeChallenge,
            CodeChallengeMethod = request.CodeChallengeMethod,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
            Used = false,
            UserId = userId
        };

        _context.AuthorizationCodes.Add(authCode);
        await _context.SaveChangesAsync();

        var redirectUrl = $"{request.RedirectUri}?code={code}&state={request.State}";

        return Redirect(redirectUrl);
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("token")]
    public async Task<IActionResult> Token([FromBody] TokenRequest request)
    {
        if (request.GrantType != "authorization_code")
            return _errorService.BadReq(ErrorCodes.InvalidRequest);

        var client = await _context.Set<OAuthClient>()
            .SingleOrDefaultAsync(c => c.ClientId == request.ClientId);
        
        if (client == null)
            return _errorService.BadReq(ErrorCodes.InvalidRequest);

        var authCode = await _context.AuthorizationCodes
            .SingleOrDefaultAsync(c => c.Code == request.Code);

        if (authCode == null || authCode.Used ||
            authCode.ExpiresAt < DateTime.UtcNow ||
            authCode.RedirectUri != request.RedirectUri ||
            authCode.ClientId != request.ClientId)
            return _errorService.BadReq(ErrorCodes.InvalidRequest);

        // PKCE
        if (authCode.CodeChallengeMethod != "S256")
            return _errorService.BadReq(ErrorCodes.InvalidRequest);

        if (string.IsNullOrEmpty(request.CodeVerifier))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        
        var hashed = WebEncoders.Base64UrlEncode(
            SHA256.HashData(Encoding.UTF8.GetBytes(request.CodeVerifier))
        );

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(hashed),
                Encoding.UTF8.GetBytes(authCode.CodeChallenge!)))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id.ToString() == authCode.UserId);
        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        if (!user.EmailVerified)
            return _errorService.AuthError(ErrorCodes.InvalidCredentials);

        string accessToken;
        string refreshTokenValue;

        try
        {
            using var tx = await _context.Database.BeginTransactionAsync();

            authCode.Used = true;

            (accessToken, var jti) = await _tokenService.GenerateJwtToken(user, false);
            refreshTokenValue = TokenService.GenerateSecureToken();

            var refreshToken = new RefreshToken
            {
                Token = TokenService.HashToken(refreshTokenValue),
                JwtId = jti,
                UserId = user.Id.ToString(),
                ExpiryDate = DateTime.UtcNow.AddDays(7)
            };

            _context.Add(refreshToken);
            await _context.SaveChangesAsync();

            await tx.CommitAsync();
        }
        catch
        {
            await _context.Database.RollbackTransactionAsync();
            throw;
        }

        return Ok(new
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            RefreshToken = refreshTokenValue,
            ExpiresIn = 1800
        });
    }
}