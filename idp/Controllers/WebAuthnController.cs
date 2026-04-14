using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using idp.Controllers.Requests.WebAuthn;
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
    private readonly ErrorService _errorService;

    public WebAuthnController(AppDbContext context, WebAuthnService webAuthnService, ErrorService errorService) {
        _context = context;
        _webAuthnService = webAuthnService;
        _errorService = errorService;
    }

    [Authorize]
    [EnableRateLimiting("auth")]
    [HttpPost("register/start")]
    public async Task<IActionResult> StartWebAuthnRegister()
    {
        var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(userId))
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        if (!Guid.TryParse(userId, out var guid))
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == guid);
        if (user == null)
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var options = _webAuthnService.StartRegistration(user.Id, user.Email);

        return Ok(options);
    }

    [Authorize]
    [EnableRateLimiting("auth")]
    [HttpPost("register/finish")]
    public async Task<IActionResult> FinishWebAuthnRegister([FromBody] WebAuthnRegisterFinishRequest request)
    {
        var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(userId))
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        if (!Guid.TryParse(userId, out var guid))
            return _errorService.AuthError(ErrorCodes.Unauthorized);

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == guid);
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
    [HttpPost("login/start")]
    public async Task<IActionResult> StartWebAuthnLogin([FromBody] WebAuthnLoginRequest request)
    {
        if (string.IsNullOrEmpty(request.Email))
            return _errorService.BadReq(ErrorCodes.InvalidRequest);
        
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email == request.Email);
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
    [HttpPost("login/finish")]
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

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim("amr", "webauthn")
            };

            var identity = new ClaimsIdentity(claims, "AuthScheme");
            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync("AuthScheme", principal);

            return Ok(new { message = "authenticated" });
        }
        catch
        {
            return _errorService.AuthError(ErrorCodes.Unauthorized);
        }
    }
}