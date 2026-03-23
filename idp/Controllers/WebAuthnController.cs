using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
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

    [HttpPost("webauthn/register/start")]
    public async Task<IActionResult> StartWebAuthnRegister([FromBody] WebAuthnRegisterRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
            return BadRequest("User not found");

        var options = _webAuthnService.StartRegistration(user.Username, user.Id.ToString());
        return Ok(options);
    }
    
    [HttpPost("webauthn/register/finish")]
    public async Task<IActionResult> FinishWebAuthnRegister([FromBody] WebAuthnRegisterFinishRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
            return BadRequest("User not found");

        var credential = await _webAuthnService.FinishRegistration(user.Id.ToString(), request.ClientResponse);

        return Ok(new
        {
            credentialId = Convert.ToBase64String(credential.CredentialIdBytes),
            message = "WebAuthn registration successful"
        });
    }
}