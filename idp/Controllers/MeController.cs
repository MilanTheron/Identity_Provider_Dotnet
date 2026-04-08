using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.RateLimiting;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class MeController : ControllerBase
{
    [Authorize]
    [EnableRateLimiting("auth")]
    [HttpGet("me")]
    public IActionResult Me()
    {
        var username = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        return Ok(new { username });
    }
}