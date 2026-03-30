using Microsoft.AspNetCore.RateLimiting;

namespace idp.config;

public class RateLimitConfig : IConfigureServices
{
    public void ConfigureServices(IConfiguration configuration, IServiceCollection services)
    {
        services.AddRateLimiter(o =>
        {
            o.AddFixedWindowLimiter("auth", opt =>
            {
                opt.Window = TimeSpan.FromMinutes(1);
                opt.PermitLimit = 5;
                opt.QueueLimit = 0;
            });
        });
    }
}