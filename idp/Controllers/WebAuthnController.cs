using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using System.IdentityModel.Tokens.Jwt;
using idp.Controllers.Requests.WebAuthn;
using idp.Models;
using idp.Services;
using idp.Models.Errors;
using idp.Data;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class WebAuthnController : ControllerBase
{
    private readonly WebAuthnService _webAuthnService;
    private readonly AppDbContext _context;
    private readonly TokenService _tokenService;
    private readonly ErrorService _errorService;

    public WebAuthnController(AppDbContext context, WebAuthnService webAuthnService, TokenService tokenService, ErrorService errorService) {
        _context = context;
        _webAuthnService = webAuthnService;
        _tokenService = tokenService;
        _errorService = errorService;
    }

    [Authorize]
    [EnableRateLimiting("auth")]
    [HttpPost("webauthn/register/start")]
    public async Task<IActionResult> StartWebAuthnRegister()
    {
        var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(userId))
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var user = await _context.Users.SingleOrDefaultAsync(u => u.Id.ToString() == userId);
        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var options = _webAuthnService.StartRegistration(user.Id, user.Username);

        return Ok(options);
    }
    
    [Authorize]
    [EnableRateLimiting("auth")]
    [HttpPost("webauthn/register/finish")]
    public async Task<IActionResult> FinishWebAuthnRegister([FromBody] WebAuthnRegisterFinishRequest request)
    {
        var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(userId))
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var user = await _context.Users.SingleOrDefaultAsync(u => u.Id.ToString() == userId);
        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        try
        {
            var credential = await _webAuthnService.FinishRegistration(user.Id, request.ClientResponse);

            return Ok(new
            {
                credentialId = Convert.ToBase64String(credential.CredentialIdBytes),
                message = "WebAuthn registration successful"
            });
        }
        catch
        {
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        }
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("webauthn/login/start")]
    public async Task<IActionResult> StartWebAuthnLogin([FromBody] WebAuthnLoginRequest request)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var creds = await _context.WebAuthnCredentials
            .Where(c => c.UserId == user.Id)
            .ToListAsync();

        if (creds.Count == 0)
            return Ok(new { });

        var options = _webAuthnService.StartLogin(user.Id, creds);

        return Ok(options);
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("webauthn/login/finish")]
    public async Task<IActionResult> FinishWebAuthnLogin([FromBody] WebAuthnLoginFinishRequest request)
    {
        byte[] credentialIdBytes;

        try
        {
            credentialIdBytes = Base64UrlEncoder.DecodeBytes(request.ClientResponse.Id);
        }
        catch
        {
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        }

        var storedCredential = await _context.WebAuthnCredentials
            .SingleOrDefaultAsync(c => c.CredentialIdBytes.SequenceEqual(credentialIdBytes));

        if (storedCredential == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var user = await _context.Users
            .SingleOrDefaultAsync(u => u.Id == storedCredential.UserId);

        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        try
        {
            var success = await _webAuthnService.FinishLogin(
                user.Id,
                request.ClientResponse,
                storedCredential
            );

            if (!success)
                return _errorService.AuthError(ErrorCodes.Unauthorized);

            var (accessToken, jti) = await _tokenService.GenerateJwtToken(user, false);
            var refreshTokenValue = TokenService.GenerateSecureToken();

            var refreshToken = new RefreshToken
            {
                Token = TokenService.HashToken(refreshTokenValue),
                JwtId = jti,
                UserId = user.Id.ToString(),
                ExpiryDate = DateTime.UtcNow.AddDays(7)
            };

            _context.Add(refreshToken);
            await _context.SaveChangesAsync();

            return Ok(new
            {
                AccessToken = accessToken,
                RefreshToken = refreshTokenValue
            });
        }
        catch
        {
            return _errorService.AuthError(ErrorCodes.Unauthorized);
        }
    }
}