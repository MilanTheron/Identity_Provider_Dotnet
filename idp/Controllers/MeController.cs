using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace idp.Controllers;

public class MeController : ControllerBase
{
    [Authorize]
    [HttpGet("/userinfo")]
    public IActionResult UserInfo()
    {
        foreach (var claim in User.Claims)
        {
            Console.WriteLine($"{claim.Type} = {claim.Value}");
        }
        
        return Ok(new
        {
            sub = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
                  ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value,
            email = User.FindFirst("email")?.Value,
            email_verified = User.FindFirst("email_verified")?.Value == "true"
        });
    }
}