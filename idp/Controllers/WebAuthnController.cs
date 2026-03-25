using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using idp.Controllers.Requests;
using idp.Services;
using idp.Data;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class WebAuthnController : ControllerBase
{
    private readonly WebAuthnService _webAuthnService;
    private readonly AppDbContext _context;
    
    public WebAuthnController(AppDbContext context, WebAuthnService webAuthnService)
    {
        _context = context;
        _webAuthnService = webAuthnService;
    }

    [Authorize]
    [HttpPost("webauthn/register/start")]
    public async Task<IActionResult> StartWebAuthnRegister([FromBody] WebAuthnRegisterRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
            return BadRequest("User not found");

        var options = _webAuthnService.StartRegistration(user.Username, user.Id);
        return Ok(options);
    }
    
    [Authorize]
    [HttpPost("webauthn/register/finish")]
    public async Task<IActionResult> FinishWebAuthnRegister([FromBody] WebAuthnRegisterFinishRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
            return BadRequest("User not found");

        var credential = await _webAuthnService.FinishRegistration(user.Id, request.ClientResponse);

        return Ok(new
        {
            credentialId = Convert.ToBase64String(credential.CredentialIdBytes),
            message = "WebAuthn registration successful"
        });
    }

    [AllowAnonymous]
    [HttpPost("webauthn/login/start")]
    public async Task<IActionResult> StartWebAuthnLogin([FromBody] WebAuthnLoginRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
            return BadRequest("User not found");
        
        var creds = _context.WebAuthnCredentials
            .Where(c => c.UserId == user.Id)
            .ToList();
        if (creds.Count == 0)
            return BadRequest("No WebAuthn credentials registered for this user");
        
        var options = _webAuthnService.StartLogin(user.Id.ToString(), creds);
        return Ok(options);
    }

    [AllowAnonymous]
    [HttpPost("webauthn/login/finish")]
    public async Task<IActionResult> FinishWebAuthnLogin([FromBody] WebAuthnLoginFinishRequest request)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Username == request.Username);

        if (user == null)
            return BadRequest("User not found");

        var credentialIdBytes = Base64UrlEncoder.DecodeBytes(request.ClientResponse.Id);

        var storedCredential = await _context.WebAuthnCredentials
            .FirstOrDefaultAsync(c =>
                c.UserId == user.Id &&
                c.CredentialIdBytes.SequenceEqual(credentialIdBytes));

        if (storedCredential == null)
            return BadRequest("Credential not registered");

        try
        {
            var success = await _webAuthnService.FinishLogin(
                user.Id,
                request.ClientResponse,
                storedCredential
            );

            if (!success)
                return Unauthorized();

            return Ok(new { message = "Login successful" });
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }
}