using idp.Controllers;
using idp.Controllers.Requests;
using idp.Data;
using idp.Models.Errors;
using idp.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Configuration;
using System.Net;
using System.Security.Cryptography;

namespace idp.Tests.Controllers;

public class AuthControllerTests
{
    private static (AuthController controller, AppDbContext db) Build(string? remoteIp = "127.0.0.1")
    {
        var db = new AppDbContext(
            new DbContextOptionsBuilder<AppDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "Hmac:Key", Convert.ToBase64String(new byte[32]) },
                { "Jwt:Issuer", "test" },
                { "Jwt:KeyId", "test-key" }
            })
            .Build();

        SecurityService.UseRsaForTesting(RSA.Create(2048));

        var errorService = new ErrorService(new HttpContextAccessor());
        var tokenService = new TokenService(db, config, NullLogger<TokenService>.Instance);
        var controller = new AuthController(db, errorService, tokenService);

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
        };

        if (remoteIp != null)
            controller.HttpContext.Connection.RemoteIpAddress =
                IPAddress.Parse(remoteIp);

        return (controller, db);
    }
    
    [Fact]
    public async Task Logout_ValidToken_Returns200()
    {
        
    }

    [Fact]
    public async Task Logout_TokenNotFound_Returns409()
    {
        var (ctrl, _) = Build();

        var result = await ctrl.Logout(new LogoutRequest { RefreshToken = "nonexistent" });

        var obj = Assert.IsType<ConflictObjectResult>(result);
        Assert.Equal(ErrorCodes.Conflict, ((ApiError)obj.Value!).Code);
    }

    [Fact]
    public async Task Logout_EmptyRefreshToken_Returns400()
    {
        var (ctrl, _) = Build();

        var result = await ctrl.Logout(new LogoutRequest { RefreshToken = "" });

        var obj = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal(ErrorCodes.InvalidRequest, ((ApiError)obj.Value!).Code);
    }

    [Fact]
    public async Task Logout_NoRemoteIp_Returns401()
    {
        var (ctrl, _) = Build(remoteIp: null);

        var result = await ctrl.Logout(new LogoutRequest { RefreshToken = "anything" });

        Assert.IsType<UnauthorizedObjectResult>(result);
    }
}