using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using System.IdentityModel.Tokens.Jwt;
using idp.Controllers.Requests.WebAuthn;
using idp.Models;
using idp.Services;
using idp.Data;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class WebAuthnController : ControllerBase
{
    private readonly WebAuthnService _webAuthnService;
    private readonly AppDbContext _context;
    private readonly TokenService _tokenService;

    public WebAuthnController(
        AppDbContext context,
        WebAuthnService webAuthnService,
        TokenService tokenService)
    {
        _context = context;
        _webAuthnService = webAuthnService;
        _tokenService = tokenService;
    }

    [Authorize]
    [EnableRateLimiting("auth")]
    [HttpPost("webauthn/register/start")]
    public async Task<IActionResult> StartWebAuthnRegister()
    {
        var username = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (username == null)
            return Unauthorized();

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null)
            return Unauthorized();

        var options = _webAuthnService.StartRegistration(user.Username, user.Id);

        return Ok(options);
    }
    
    [Authorize]
    [EnableRateLimiting("auth")]
    [HttpPost("webauthn/register/finish")]
    public async Task<IActionResult> FinishWebAuthnRegister([FromBody] WebAuthnRegisterFinishRequest request)
    {
        var username = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (username == null)
            return Unauthorized();

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null)
            return Unauthorized();

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
            return BadRequest("Registration failed");
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
            return Ok(new { }); 

        var creds = await _context.WebAuthnCredentials
            .Where(c => c.UserId == user.Id)
            .ToListAsync();

        if (creds.Count == 0)
            return Ok(new { });

        var options = _webAuthnService.StartLogin(user.Id.ToString(), creds);

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
            return BadRequest("Invalid credential format");
        }

        var storedCredential = await _context.WebAuthnCredentials
            .FirstOrDefaultAsync(c => c.CredentialIdBytes.SequenceEqual(credentialIdBytes));

        if (storedCredential == null)
            return Unauthorized("Authentication failed");

        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id == storedCredential.UserId);

        if (user == null)
            return Unauthorized("Authentication failed");

        try
        {
            var success = await _webAuthnService.FinishLogin(
                user.Id,
                request.ClientResponse,
                storedCredential
            );

            if (!success)
                return Unauthorized("Authentication failed");

            var accessToken = await _tokenService.GenerateJwtToken(user, true);
            var refreshTokenValue = TokenService.GenerateRefreshToken();

            var refreshToken = new RefreshToken
            {
                Token = _tokenService.HashToken(refreshTokenValue),
                JwtId = Guid.NewGuid().ToString(),
                UserId = user.Username,
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
            return Unauthorized("Authentication failed");
        }
    }
}