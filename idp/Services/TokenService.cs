using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using idp.Data;
using idp.Models;

namespace idp.Services;

public class TokenService
{
    private readonly AppDbContext _context;
    private readonly IConfiguration _configuration;
    private readonly ILogger<TokenService> _logger;
    private readonly byte[] _hmacKey;

    public TokenService(AppDbContext context, IConfiguration configuration, ILogger<TokenService> logger)
    {
        _context = context;
        _configuration = configuration;
        _logger = logger;
        
        var keyString = configuration["Hmac:Key"];

        if (string.IsNullOrWhiteSpace(keyString))
            throw new Exception("Hmac:Key is missing");

        try
        {
            _hmacKey = Convert.FromBase64String(keyString);
        }
        catch (FormatException)
        {
            throw new Exception("Hmac:Key is not valid Base64");
        }
    }

    public async Task<(string token, string jti)> GenerateJwtToken(User user, bool mfaVerified, string scope, string clientId)
    {
        _logger.LogInformation("Generating JWT for user {UserId}, MFA: {Mfa}", user.Id, mfaVerified);
        
        var bytes = RandomNumberGenerator.GetBytes(32);
        var jti = WebEncoders.Base64UrlEncode(bytes);
        var now = DateTime.UtcNow;
        
        Console.WriteLine($"Generating JWT for user {user.Id}, email: {user.Email}, " +
                          $"MFA: {mfaVerified}, Scope: {scope}, ClientId: {clientId}");
        
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()), // user identity
            new Claim(JwtRegisteredClaimNames.Jti, jti), // token identity
            new Claim("email", user.Email),
            new Claim("scope", scope),
            new Claim("client_id", clientId),
            new Claim("email_verified", user.EmailVerified ? "true" : "false"),
            new Claim("mfa", mfaVerified ? "true" : "false"),
            new Claim(JwtRegisteredClaimNames.Iat,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64)
        };
        
        if (scope.Contains("profile"))
            claims.Add(new Claim(JwtRegisteredClaimNames.Name, user.Email.Split('@')[0]));
        
        var rsa = SecurityService.Rsa;
        var keyId = _configuration["Jwt:KeyId"];
        var key = new RsaSecurityKey(rsa) { KeyId = keyId };
        var creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
        var expiry = now.AddMinutes(30);
        
        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: clientId,
            claims: claims,
            notBefore: now,
            expires: expiry,
            signingCredentials: creds);
        
        await SecurityService.StoreJtiAsync(_context, jti, expiry);
        
        return (new JwtSecurityTokenHandler().WriteToken(token), jti);
    }
    
    public async Task<string> GenerateIdToken(User user, string clientId, string? nonce)
    {
        var now = DateTime.UtcNow;
        var expiry = now.AddMinutes(30);
    
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim("email_verified", user.EmailVerified ? "true" : "false"),
            new Claim("azp", clientId),
            new Claim(JwtRegisteredClaimNames.Aud, clientId),
            new Claim(JwtRegisteredClaimNames.Iat,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64),
            new Claim(JwtRegisteredClaimNames.Exp,
                DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64),
            new Claim(JwtRegisteredClaimNames.Nbf,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64)
        };
    
        if (!string.IsNullOrEmpty(nonce))
            claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));
    
        claims.Add(new Claim(JwtRegisteredClaimNames.Name, user.Email.Split('@')[0]));
    
        var rsa = SecurityService.Rsa;
        var keyId = _configuration["Jwt:KeyId"];
        var key = new RsaSecurityKey(rsa) { KeyId = keyId };
        var creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
    
        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: clientId,
            claims: claims,
            notBefore: now,
            expires: expiry,
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }


    public static string GenerateSecureToken()
    {
        using var rng = RandomNumberGenerator.Create();
        var randomNumber = new byte[64];
        rng.GetBytes(randomNumber);
        return WebEncoders.Base64UrlEncode(randomNumber);
    }
    
    public string HashToken(string token)
    {
        using var hmac = new HMACSHA256(_hmacKey);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(token));
        return Convert.ToBase64String(hash);
    }
}