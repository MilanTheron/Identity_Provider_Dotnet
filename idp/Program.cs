using idp.config;

var myApp = new MyApp();
await myApp.RunAppAsync(args);

public class MyApp : BaseWebApp
{
    protected override void RegisterConfiguration(string[] args)
    {
        // Logger
        Register(new LoggingConfig());
        
        // Services
        Register(new ServiceRegistration());

        // JWT & Auth
        Register(new JwtAuthConfig());

        // Rate limiter
        Register(new RateLimitConfig());

        // OAuth client seeding
        Register(new OAuthSeedConfig());

        // Dev/Prod pipeline (exception handling, HTTPS, HSTS)
        Register(new PipelineConfig());

        // Security headers middleware
        Register(new SecurityHeadersConfig());

        // Dev-only --cleanDB
        Register(new CleanDbConfig(args));
    }
}