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

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpGet("authorize")]
    public async Task<IActionResult> Authorize([FromQuery] AuthorizeRequest request)
    {
        Console.WriteLine("=== AUTHORIZE ===");
        Console.WriteLine($"client_id: {request.ClientId}");
        Console.WriteLine($"redirect_uri: {request.RedirectUri}");
        Console.WriteLine($"state: {request.State}");
        Console.WriteLine($"code_challenge: {request.CodeChallenge}");
        Console.WriteLine($"User is authenticated: {User.Identity?.IsAuthenticated}");
        Console.WriteLine($"Cookie keys count: {HttpContext.Request.Cookies.Keys.Count}");
        Console.WriteLine($"Cookie: {HttpContext.Request.Headers.Cookie.ToString()}");
        Console.WriteLine("Auth type: " + User.Identity?.AuthenticationType);
        Console.WriteLine("Is auth: " + User.Identity?.IsAuthenticated);
        Console.WriteLine("Claims: " + string.Join(",", User.Claims.Select(c => $"{c.Type}:{c.Value}")));
        
        if (User.Identity == null || !User.Identity.IsAuthenticated)
        {
            var returnUrl = $"{Request.Path}{Request.QueryString}";
            return Redirect($"/Auth?Mode=register&returnUrl={Uri.EscapeDataString(returnUrl)}");
        }

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
        
        var userIdStr = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

        if (!Guid.TryParse(userIdStr, out var userId))
            return BadRequest(new { error = "invalid_user_id" });

        var user = await _context.Users.FindAsync(userId);
        if (user != null && !user.EmailVerified)
            return BadRequest(ErrorCodes.EmailNotVerified);
        
        if (string.IsNullOrEmpty(request.CodeChallenge) ||
            request.CodeChallenge.Length > 128 ||
            !Regex.IsMatch(request.CodeChallenge, @"^[A-Za-z0-9\-_]+$"))
            return BadRequest(new { error = "invalid_code_challenge" });
        
        if (string.IsNullOrEmpty(request.CodeChallenge) || request.CodeChallengeMethod != "S256")
            return BadRequest(new { error = "invalid_pkce" });
        
        if (string.IsNullOrEmpty(request.ClientId))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        
        if (string.IsNullOrEmpty(request.RedirectUri))
            return BadRequest(new { error = "invalid_RedirectUri" });
        
        var code = TokenService.GenerateSecureToken();
        
        var scope = string.IsNullOrWhiteSpace(request.Scope)
            ? "openid"
            : request.Scope;
        
        var authCode = new AuthorizationCode
        {
            Code = code,
            ClientId = request.ClientId,
            RedirectUri = request.RedirectUri,
            Nonce = request.Nonce,
            CodeChallenge = request.CodeChallenge,
            CodeChallengeMethod = request.CodeChallengeMethod,
            Scope = scope,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
            Used = false,
            UserId = userIdStr
        };
        
        Console.WriteLine($"challenge: {authCode.CodeChallenge}");
        Console.WriteLine($"method: {authCode.CodeChallengeMethod}");
        
        _context.AuthorizationCodes.Add(authCode);
        await _context.SaveChangesAsync();
        
        var redirectUrl = $"{request.RedirectUri}?code={code}&state={request.State}";
        
        return Redirect(redirectUrl);
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Token([FromForm] TokenRequest request)
    {
        if (request.GrantType != "authorization_code")
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        
        string? clientId = request.ClientId;
        string? clientSecret = request.ClientSecret;

        var authHeader = Request.Headers["Authorization"].FirstOrDefault();

        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Basic "))
        {
            var encoded = authHeader.Substring("Basic ".Length);
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var parts = decoded.Split(':', 2);

            if (parts.Length == 2)
            {
                clientId = parts[0];
                clientSecret = parts[1];
            }
        }
        
        var client = await _context.Set<OAuthClient>()
            .SingleOrDefaultAsync(c => c.ClientId == clientId);

        if (client == null || client.ClientSecret != clientSecret)
            return _errorService.AuthError("invalid_client");
        
        if (string.IsNullOrEmpty(request.Code))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        
        var authCode = await _context.AuthorizationCodes
            .SingleOrDefaultAsync(c => c.Code == request.Code);
        
        if (authCode == null || authCode.Used ||
            authCode.ExpiresAt < DateTime.UtcNow ||
            authCode.RedirectUri != request.RedirectUri ||
            authCode.ClientId != clientId)
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        
        var scope = request.Scope ?? authCode.Scope;

        if (string.IsNullOrEmpty(scope))
            return _errorService.BadReq("invalid_scope");

        var requestedScopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (!requestedScopes.Contains("openid") &&
            requestedScopes.Any(s => !client.AllowedScopes.Contains(s)))
            return _errorService.BadReq("invalid_scope");
        
        Console.WriteLine("=== TOKEN ===");
        Console.WriteLine($"client_id: {client.ClientId}");
        Console.WriteLine($"redirect_uri: {request.RedirectUri}");
        Console.WriteLine($"code: {request.Code}");
        Console.WriteLine($"code_verifier: {request.CodeVerifier}");
        Console.WriteLine($"code_challenge: {authCode.CodeChallenge}");
        Console.WriteLine($"code_challenge_method: {authCode.CodeChallengeMethod}");
        
        // PKCE
        if (authCode.CodeChallengeMethod != "S256")
        {
            Console.WriteLine($"Unsupported code challenge method: {authCode.CodeChallengeMethod}");
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        }
        
        if (string.IsNullOrEmpty(request.CodeVerifier))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);

        var hashed = WebEncoders.Base64UrlEncode(
            SHA256.HashData(Encoding.UTF8.GetBytes(request.CodeVerifier))
        );
        
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(hashed),
                Encoding.UTF8.GetBytes(authCode.CodeChallenge)))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        
        if (!Guid.TryParse(authCode.UserId, out var guid))
            return _errorService.AuthError(ErrorCodes.Unauthorized);
        
        var user = await _context.Users.FindAsync(guid);
        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);
        
        if (!user.EmailVerified)
            return _errorService.AuthError(ErrorCodes.InvalidCredentials);
        
        if (string.IsNullOrWhiteSpace(user.Email))
            throw new InvalidOperationException("User.Email is required for token generation");
        
        string accessToken;
        string refreshTokenValue;

        await using var tx = await _context.Database.BeginTransactionAsync();

        try
        {
            authCode.Used = true;

            (accessToken, var jti) = await _tokenService.GenerateJwtToken(
                user, false, scope, clientId);

            refreshTokenValue = TokenService.GenerateSecureToken();

            var refreshToken = new RefreshToken
            {
                Token = _tokenService.HashToken(refreshTokenValue),
                JwtId = jti,
                UserId = user.Id,
                ExpiryDate = DateTime.UtcNow.AddDays(7)
            };

            _context.Add(refreshToken);
            await _context.SaveChangesAsync();

            await tx.CommitAsync();
        }
        catch
        {
            await tx.RollbackAsync();
            throw;
        }
        
        var idToken = await _tokenService.GenerateIdToken(
            user,
            clientId,
            authCode.Nonce
        );
        
        return Ok(new
        {
            access_token = accessToken,
            id_token = idToken,
            token_type = "Bearer",
            refresh_token = refreshTokenValue,
            expires_in = 1800
        });
    }
}