using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace idp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class MeController : ControllerBase
{
    [Authorize]
    [HttpGet("me")]
    public IActionResult Me()
    {
        var username = User.Identity?.Name;
        return Ok(new { username });
    }
}