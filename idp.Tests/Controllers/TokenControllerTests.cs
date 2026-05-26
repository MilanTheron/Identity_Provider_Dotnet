using idp.Controllers;
using idp.Controllers.Requests;
using idp.Data;
using idp.Models;
using idp.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using System.Net;
using System.Text.Json;

namespace idp.Tests.Controllers;

public class TokenControllerTests
{
    private static (TokenController ctrl, AppDbContext db, TokenService tokenService) Build(string? remoteIp = "127.0.0.1")
    {
        var db = new AppDbContext(
            new DbContextOptionsBuilder<AppDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
                .Options);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "Hmac:Key", Convert.ToBase64String(new byte[32]) },
                { "Jwt:Issuer", "test" },
                { "Jwt:KeyId", "test-key" }
            })
            .Build();

        SecurityService.UseRsaForTesting(System.Security.Cryptography.RSA.Create(2048));

        var errorService = new ErrorService(new HttpContextAccessor());
        var tokenService = new TokenService(db, config, NullLogger<TokenService>.Instance);
        var controller = new TokenController(db, tokenService, errorService);

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
        };

        if (remoteIp != null)
            controller.HttpContext.Connection.RemoteIpAddress = IPAddress.Parse(remoteIp);

        var accessor = new HttpContextAccessor { HttpContext = controller.HttpContext };

        return (controller, db, tokenService);
    }

    [Fact]
    public async Task Refresh_ValidToken_ReturnsNewTokens()
    {
        var (ctrl, db, tokenService) = Build();

        var user = new User { Id = Guid.NewGuid(), Email = "test@test.com", EmailVerified = true, PasswordHash = "" };
        db.Users.Add(user);

        var plainRefresh = TokenService.GenerateSecureToken();
        var hashed = tokenService.HashToken(plainRefresh);

        var stored = new RefreshToken
        {
            Token = hashed,
            JwtId = "jti",
            UserId = user.Id,
            ExpiryDate = DateTime.UtcNow.AddDays(1),
            IsRevoked = false,
            IsUsed = false,
            CreatedAt = DateTime.UtcNow,
            CreatedByIp = "127.0.0.1",
            MfaVerified = false,
            Scope = "openid",
            ClientId = "client"
        };

        db.RefreshTokens.Add(stored);
        await db.SaveChangesAsync();

        var result = await ctrl.Refresh(new RefreshRequest { RefreshToken = plainRefresh });

        var ok = Assert.IsType<OkObjectResult>(result);
        var json = JsonSerializer.Serialize(ok.Value);
        var obj = JsonSerializer.Deserialize<Dictionary<string, string>>(json)!;
        Assert.True(obj.ContainsKey("AccessToken"));
        Assert.True(obj.ContainsKey("RefreshToken"));

        var reloaded = await db.RefreshTokens.FindAsync(stored.Id);
        Assert.True(reloaded.IsUsed);
        Assert.True(reloaded.IsRevoked);
        Assert.NotNull(reloaded.ReplacedByToken);
    }

    [Fact]
    public async Task Refresh_RevokedToken_Returns401()
    {
        var (ctrl, db, tokenService) = Build();

        var user = new User { Id = Guid.NewGuid(), Email = "a@a.com", EmailVerified = true, PasswordHash = "" };
        db.Users.Add(user);

        var plain = TokenService.GenerateSecureToken();
        var hashed = tokenService.HashToken(plain);

        var stored = new RefreshToken
        {
            Token = hashed,
            JwtId = "jti",
            UserId = user.Id,
            ExpiryDate = DateTime.UtcNow.AddDays(1),
            IsRevoked = true,
            IsUsed = false
        };

        db.RefreshTokens.Add(stored);
        await db.SaveChangesAsync();

        var result = await ctrl.Refresh(new RefreshRequest { RefreshToken = plain });

        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    [Fact]
    public async Task Refresh_NoRemoteIp_Returns401()
    {
        var (ctrl, db, tokenService) = Build(remoteIp: null);

        var result = await ctrl.Refresh(new RefreshRequest { RefreshToken = "anything" });

        Assert.IsType<UnauthorizedObjectResult>(result);
    }
}

