using idp.Data;
using idp.Models;

namespace idp.config;

public class OAuthSeedConfig : IConfigureApp
{
    public void ConfigureApp(WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        if (!db.OAuthClients.Any(c => c.ClientId == "myclient"))
        {
            db.OAuthClients.Add(new OAuthClient
            {
                ClientId = "myclient",
                RedirectUris = new List<string> { "https://localhost:5002/callback" },
                RequirePkce = true
            });
            db.SaveChanges();
        }
    }
}