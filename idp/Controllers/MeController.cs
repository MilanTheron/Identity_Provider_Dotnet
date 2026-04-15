using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.RateLimiting;

namespace idp.Controllers;

[ApiController]
[Route("userinfo")]
public class MeController : ControllerBase
{
    [Authorize]
    public IActionResult UserInfo()
    {
        return Ok(new
        {
            sub = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value,
            email = User.FindFirst("email")?.Value,
            email_verified = User.FindFirst("email_verified")?.Value == "true"
        });
    }
}