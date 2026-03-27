using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using idp.Services;

namespace idp.Controllers;

[Route(".well-known")]
[ApiController]
public class WellKnownController : ControllerBase
{
    private readonly IConfiguration _configuration;
    
    public WellKnownController(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    [AllowAnonymous]
    [HttpGet("openid-configuration")]
    public IActionResult OpenIdConfiguration()
    {
        var issuer = $"{Request.Scheme}://{Request.Host}";
        var config = new
        {
            issuer = issuer,
            authorization_endpoint = $"{issuer}/api/oauth/authorize",
            token_endpoint = $"{issuer}/api/oauth/token",
            
            webAuthnRegisterStart_endpoint = $"{issuer}api/webauthn/register/start",
            webAuthnRegisterFinish_endpoint = $"{issuer}api/webauthn/register/finish",
            webAuthnLoginStart_endpoint = $"{issuer}api/webauthn/login/start",
            webAuthnLoginFinish_endpoint = $"{issuer}api/webauthn/login/finish",
            
            register_endpoint = $"{issuer}api/register",
            totp_endpoint = $"{issuer}/api/setup-totp",
            login_endpoint =  $"{issuer}api/login",
            logout_endpoint = $"{issuer}api/logout",
            changePassword_endpoint = $"{issuer}api/change-password",
            userinfo_endpoint = $"{issuer}/api/me",
            
            jwks_uri = $"{issuer}/.well-known/jwks",
        };
        return Ok(config);
    }

    [AllowAnonymous]
    [HttpGet("jwks")]
    public IActionResult Jwks()
    {
        var rsa = SecurityService.Rsa;
        var parameters = rsa.ExportParameters(false);

        var jwk = new
        {
            kty = "RSA",
            kid = _configuration["Jwt:KeyId"],
            use = "sig",
            alg = "RS256",
            n = Base64UrlEncoder.Encode(parameters.Modulus),
            e = Base64UrlEncoder.Encode(parameters.Exponent)
        };

        return Ok(new { keys = new[] { jwk } });
    }
}