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
        var scheme = Request.Scheme;
        var host = Request.Host.ToString();
        
        var publicIssuer = _configuration["Jwt:Issuer"];
        
        string endpointBase;
        if (host.StartsWith("localhost") || host.StartsWith("127.0.0.1"))
            endpointBase = $"{scheme}://localhost:5000";
        else
            endpointBase = $"{scheme}://idp:8080";

        var config = new
        {
            issuer = publicIssuer,

            authorization_endpoint = $"{endpointBase}/api/oauth/authorize",
            token_endpoint = $"{endpointBase}/api/oauth/token",
            userinfo_endpoint = $"{endpointBase}/userinfo",
            jwks_uri = $"{endpointBase}/.well-known/jwks",

            response_types_supported = new[] { "code" },
            subject_types_supported = new[]
            {
                "public", 
                "pairwise"
            },
            id_token_signing_alg_values_supported = new[] { "RS256" },

            scopes_supported = new[] { "openid", "profile", "email" },

            grant_types_supported = new[]
            {
                "authorization_code",
                "refresh_token"
            },

            code_challenge_methods_supported = new[] { "S256" },
            
            response_modes_supported = new[]
            {
                "query",
                "fragment",
                "form_post"
            },

            token_endpoint_auth_methods_supported = new[]
            {
                "client_secret_post"
            },

            claims_supported = new[]
            {
                "sub", "email", "email_verified"
            }
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