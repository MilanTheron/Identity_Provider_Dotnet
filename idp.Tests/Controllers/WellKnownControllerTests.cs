using idp.Controllers;
using idp.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Text.Json;
using System.Security.Cryptography;

namespace idp.Tests.Controllers;

public class WellKnownControllerTests
{
    private static WellKnownController Build()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "Jwt:Issuer", "https://test" },
                { "Jwt:KeyId", "test-key" }
            })
            .Build();

        SecurityService.UseRsaForTesting(RSA.Create(2048));

        return new WellKnownController(config);
    }

    [Fact]
    public void OpenIdConfiguration_ReturnsIssuerAndEndpoints()
    {
        var ctrl = Build();

        var result = ctrl.OpenIdConfiguration();

        var ok = Assert.IsType<OkObjectResult>(result);
        var dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(JsonSerializer.Serialize(ok.Value))!;

        Assert.Equal("https://test", dict["issuer"].GetString());
        Assert.Contains("/api/oauth/authorize", dict["authorization_endpoint"].GetString());
        Assert.Contains("/userinfo", dict["userinfo_endpoint"].GetString());
        Assert.Contains("/jwks", dict["jwks_uri"].GetString());
    }

    [Fact]
    public void Jwks_ReturnsKeyWithKidAndModulusExponent()
    {
        var ctrl = Build();

        var result = ctrl.Jwks();

        var ok = Assert.IsType<OkObjectResult>(result);
        var dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(JsonSerializer.Serialize(ok.Value))!;

        Assert.True(dict.ContainsKey("keys"));
        var keys = dict["keys"].EnumerateArray().ToArray();
        Assert.Single(keys);

        var jwk = keys[0];
        Assert.Equal("test-key", jwk.GetProperty("kid").GetString());
        Assert.Equal("RSA", jwk.GetProperty("kty").GetString());
        Assert.True(jwk.TryGetProperty("n", out var n));
        Assert.True(jwk.TryGetProperty("e", out var e));
        Assert.False(string.IsNullOrEmpty(n.GetString()));
        Assert.False(string.IsNullOrEmpty(e.GetString()));
    }
}

