using idp.Data;

namespace idp.config;

public class CleanDbConfig : IConfigureApp
{
    private readonly string[] _args;

    public CleanDbConfig(string[] args)
    {
        _args = args;
    }

    public void ConfigureApp(WebApplication app)
    {
        if (_args.Contains("--cleanDB"))
        {
            using var scope = app.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            Console.WriteLine("Deleting database...");
            db.Database.EnsureDeleted();

            Console.WriteLine("Recreating database...");
            db.Database.EnsureCreated();

            Console.WriteLine("Database fully removed and recreated");

            // Stop the app
            Environment.Exit(0);
        }
    }
}