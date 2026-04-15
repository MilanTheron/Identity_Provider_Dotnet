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
            
            //OAuth
            authorization_endpoint = $"{issuer}/api/oauth/authorize",
            token_endpoint = $"{issuer}/api/oauth/token",
            
            // Webauthn
            webAuthnRegisterStart_endpoint = $"{issuer}/api/webauthn/register/start",
            webAuthnRegisterFinish_endpoint = $"{issuer}/api/webauthn/register/finish",
            webAuthnLoginStart_endpoint = $"{issuer}/api/webauthn/login/start",
            webAuthnLoginFinish_endpoint = $"{issuer}/api/webauthn/login/finish",
            
            // Authentication
            register_endpoint = $"{issuer}/api/auth/register",
            login_endpoint =  $"{issuer}/api/auth/login",
            logout_endpoint = $"{issuer}/api/auth/logout",
            logout_session_endpoint = $"{issuer}/api/auth/logout/session",
            
            // Email
            verify_email_endpoint = $"{issuer}/api/email/verify-email",
            resend_verification_endpoint = $"{issuer}/api/email/resend-verification",
            forgot_password_endpoint = $"{issuer}/api/email/forgot-password",
            reset_password_endpoint = $"{issuer}/api/email/reset-password",
            
            // Userinfo
            userinfo_endpoint = $"{issuer}/userinfo",
            
            // Totp
            setup_totp_endpoint = $"{issuer}/api/totp/setup-totp",
            verify_totp_endpoint = $"{issuer}/api/totp/verify-totp",
            request_totp_fallback_endpoint = $"{issuer}/api/totp/request-totp-fallback",
            verify_totp_fallback_endpoint = $"{issuer}/api/totp/verify-totp-fallback",
            
            // OpenID Connect metadata
            response_types_supported = new[] { "code" },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" },
            scopes_supported = new[] { "openid", "profile", "email" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post" },
            
            jwks_uri = $"{issuer}/.well-known/jwks"
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