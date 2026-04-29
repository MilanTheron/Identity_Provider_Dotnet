using idp.Data;
using idp.Models;

namespace idp.config;

public class OAuthSeedConfig : IConfigureApp
{
    public void ConfigureApp(WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        if (!db.OAuthClients.Any(c => c.ClientId == "miniflux"))
        {
            db.OAuthClients.Add(new OAuthClient
            {
                ClientId = "miniflux",
                RedirectUris = new List<string> 
                { 
                    "http://miniflux.localtest.me/oauth2/oidc/callback"
                },
                ClientSecret = "super-secret",
                RequirePkce = true,
                AllowedScopes = new List<string> { "openid", "profile", "email" }
            });
            db.SaveChanges();
        }
    }
}