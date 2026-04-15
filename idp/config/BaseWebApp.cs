using idp.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;

namespace idp.config;

public abstract class BaseWebApp
{
    private readonly List<IConfigure> _configs = new();

    protected abstract void RegisterConfiguration(string[] args);

    protected void Register(IConfigure config) => _configs.Add(config);

    public async Task RunAppAsync(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        RegisterConfiguration(args);

        foreach (var c in _configs.OfType<IConfigureServices>())
            c.ConfigureServices(builder.Configuration, builder.Services);

        builder.Services.AddRazorPages();
        builder.Services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo("/app/keys"))
            .SetApplicationName("idp");
        
        var app = builder.Build();
        
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            db.Database.Migrate();
        }
        
        foreach (var c in _configs.OfType<IConfigureApp>())
            c.ConfigureApp(app);

        await app.RunAsync();
    }
}