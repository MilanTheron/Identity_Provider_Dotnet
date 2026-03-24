using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace idp.Controllers;

[Route(".well-known")]
[ApiController]
public class WellKnownController : ControllerBase
{
    [HttpGet("openid-configuration")]
    public IActionResult OpenIdConfiguration()
    {
        var issuer = $"{Request.Scheme}://{Request.Host}";
        var config = new
        {
            issuer = issuer,
            authorization_endpoint = $"{issuer}/api/oauth/authorize",
            token_endpoint = $"{issuer}/api/oauth/token",
            userinfo_endpoint = $"{issuer}/api/me",
            totp_endpoint = $"{issuer}/api/setup-totp",
            webAuthnRegisterStart_endpoint = $"{issuer}api/webauthn/register/start",
            webAuthnRegisterFinish_endpoint = $"{issuer}api/webauthn/register/finish",
            webAuthnLoginStart_endpoint = $"{issuer}api/webauthn/login/start",
            webAuthnLoginFinish_endpoint = $"{issuer}api/webauthn/login/finish",
            login_endpoint =  $"{issuer}api/login",
            logout_endpoint = $"{issuer}api/logout",
            changePassword_endpoint = $"{issuer}api/change-password",
            register_endpoint = $"{issuer}api/register",
        };
        return Ok(config);
    }
}