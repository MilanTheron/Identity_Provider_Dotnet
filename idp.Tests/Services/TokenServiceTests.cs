using idp.Services;
using idp.Models;
using idp.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using System.IdentityModel.Tokens.Jwt;

namespace idp.Tests.Services;

public class TokenServiceTests
{
    private readonly TokenService _tokenService;

    public TokenServiceTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase("TestDb")
            .Options;

        var dbContext = new AppDbContext(options);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "Hmac:Key", Convert.ToBase64String(new byte[32]) },
                { "Jwt:Issuer", "test" },
                { "Jwt:KeyId", "test-key" }
            })
            .Build();

        _tokenService = new TokenService(
            dbContext,
            config,
            NullLogger<TokenService>.Instance
        );
    }

    [Fact]
    public async Task GenerateJwtToken_ReturnsNonEmptyString()
    {
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = "test@test.com",
            PasswordHash = "hash",
            EmailVerified = true
        };

        var (token, _) = await _tokenService.GenerateJwtToken(
            user,
            true,
            "profile",
            "client"
        );

        Assert.False(string.IsNullOrWhiteSpace(token));
    }

    [Fact]
    public async Task GenerateJwtToken_ParsesCorrectly()
    {
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = "test@test.com",
            PasswordHash = "hash",
            EmailVerified = true
        };

        var (token, jti) = await _tokenService.GenerateJwtToken(
            user,
            true,
            "profile",
            "client"
        );

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        Assert.Equal(user.Id.ToString(), jwtToken.Subject);
        Assert.Equal("client", jwtToken.Audiences.FirstOrDefault());
        Assert.Equal(jti, jwtToken.Id);
    }
}