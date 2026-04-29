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
        Console.WriteLine("=== Claims ===");
        foreach (var claim in User.Claims)
            Console.WriteLine($"{claim.Type} = {claim.Value}");
        
        var scope = User.FindFirst("scope")?.Value ?? "";

        var response = new Dictionary<string, object>
        {
            { "sub", User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value 
                     ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value }
        };

        if (scope.Contains("email"))
        {
            response["email"] = User.FindFirst("email")?.Value;
            response["email_verified"] = User.FindFirst("email_verified")?.Value == "true";
        }

        if (scope.Contains("profile"))
        {
            var name = User.FindFirst(JwtRegisteredClaimNames.Name)?.Value;
            if (!string.IsNullOrEmpty(name))
                response["name"] = name;
        }
        
        Console.WriteLine("=== Response ===");
        foreach (KeyValuePair<string, object> kvp in response)
            Console.WriteLine("{0}: {1}", kvp.Key, kvp.Value);
        
        return Ok(response);
    }
}