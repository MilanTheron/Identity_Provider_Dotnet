using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using idp.Models;

namespace idp.Services;

public class TokenService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<TokenService> _logger;

    public TokenService(IConfiguration configuration, ILogger<TokenService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<(string token, string jti)> GenerateJwtToken(User user, bool mfaVerified)
    {
        _logger.LogInformation("Generating JWT for user {UserId}, MFA: {Mfa}", user.Id, mfaVerified);
        
        var bytes = RandomNumberGenerator.GetBytes(32);
        var jti = WebEncoders.Base64UrlEncode(bytes);

        var now = DateTime.UtcNow;

        _logger.LogInformation("JWT generated for user {UserId} with JTI {Jti}", user.Id, jti);
        
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()), // user identity
            new Claim(JwtRegisteredClaimNames.Jti, jti), // token identity
            new Claim("email", user.Email),
            new Claim("mfa", mfaVerified ? "true" : "false"),
            new Claim("email_verified", user.EmailVerified ? "true" : "false"),
            new Claim(JwtRegisteredClaimNames.Iat,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64)
        };

        var rsa = SecurityService.Rsa;
        var keyId = _configuration["Jwt:KeyId"];
        var key = new RsaSecurityKey(rsa)
        {
            KeyId = keyId
        };

        var creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
        var expiry = now.AddMinutes(30);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            notBefore: now,
            expires: expiry,
            signingCredentials: creds);
        
        await SecurityService.StoreJtiAsync(jti, expiry);

        return (new JwtSecurityTokenHandler().WriteToken(token), jti);
    }

    public static string GenerateSecureToken()
    {
        using var rng = RandomNumberGenerator.Create();
        var randomNumber = new byte[64];
        rng.GetBytes(randomNumber);
        return WebEncoders.Base64UrlEncode(randomNumber);
    }
    
    public static string HashToken(string token)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
        return WebEncoders.Base64UrlEncode(bytes);
    }
}