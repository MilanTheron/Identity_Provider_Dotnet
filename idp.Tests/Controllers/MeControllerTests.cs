using idp.Controllers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace idp.Tests.Controllers;

public class MeControllerTests
{
    private static MeController Build(params Claim[] claims)
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
        var controller = new MeController();
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = user }
        };
        return controller;
    }

    [Fact]
    public void UserInfo_WithEmailScope_ReturnsEmailAndVerification()
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, "user-1"),
            new Claim("scope", "openid email profile"),
            new Claim("email", "alice@example.com"),
            new Claim("email_verified", "true")
        };

        var ctrl = Build(claims);

        var result = ctrl.UserInfo();

        var ok = Assert.IsType<OkObjectResult>(result);
        var dict = Assert.IsType<Dictionary<string, object>>(ok.Value);

        Assert.Equal("user-1", dict["sub"]);
        Assert.Equal("alice@example.com", dict["email"]);
        Assert.True((bool)dict["email_verified"]);
    }

    [Fact]
    public void UserInfo_WithoutEmailScope_OmitsEmail()
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, "user-2"),
            new Claim("scope", "openid profile"),
            new Claim(JwtRegisteredClaimNames.Name, "Alice")
        };

        var ctrl = Build(claims);

        var result = ctrl.UserInfo();

        var ok = Assert.IsType<OkObjectResult>(result);
        var dict = Assert.IsType<Dictionary<string, object>>(ok.Value);

        Assert.Equal("user-2", dict["sub"]);
        Assert.False(dict.ContainsKey("email"));
        Assert.Equal("Alice", dict["name"]);
    }
}

