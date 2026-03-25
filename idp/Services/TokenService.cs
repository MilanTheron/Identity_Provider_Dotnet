using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using idp.Models;

namespace idp.Services;

public class TokenService
{
    private readonly IConfiguration _configuration;
    private readonly SecurityService _securityService;

    public TokenService(IConfiguration configuration, SecurityService securityService)
    {
        _configuration = configuration;
        _securityService = securityService;
    }

    public async Task<string> GenerateJwtToken(User user, bool mfaVerified)
    {
        var jti = Guid.NewGuid().ToString();

        var now = DateTime.UtcNow;

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Username),
            new Claim(JwtRegisteredClaimNames.Jti, jti),
            new Claim(JwtRegisteredClaimNames.Iat,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64),
            new Claim("mfa", mfaVerified ? "true" : "false")
        };

        var keyString = _configuration["Jwt:Key"] 
                        ?? throw new InvalidOperationException("Jwt:Key not configured");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyString));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expiry = now.AddMinutes(30);
        
        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            notBefore: now,
            expires: expiry,
            signingCredentials: creds);
        
        await _securityService.StoreJtiAsync(jti, expiry);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public static string GenerateRefreshToken()
    {
        using var rng = RandomNumberGenerator.Create();
        var randomNumber = new byte[64];
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
    
    public string HashToken(string token)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
        return Convert.ToBase64String(bytes);
    }
}

