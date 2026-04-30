using Microsoft.AspNetCore.HttpOverrides;

namespace idp.config;

public class PipelineConfig : IConfigureApp
{
    public void ConfigureApp(WebApplication app)
    {
        var forwardedHeadersOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor |
                               ForwardedHeaders.XForwardedProto |
                               ForwardedHeaders.XForwardedHost
        };

        forwardedHeadersOptions.KnownNetworks.Add(
            new IPNetwork(System.Net.IPAddress.Parse("172.18.0.0"), 16)
        );

        app.UseForwardedHeaders(forwardedHeadersOptions);
        
        // Exception handling / HSTS / HTTPS
        app.UseExceptionHandler("/Error");
        app.UseHsts();
        if (!app.Environment.IsDevelopment())
        {
            app.UseHttpsRedirection();
        }

        // Rate Limiter
        app.UseRateLimiter();
        
        // Favicon
        app.UseStaticFiles();
        
        // Routing
        app.UseRouting();

        // Authentication & authorization
        app.UseAuthentication();
        app.UseAuthorization();

        // Map controllers
        app.MapControllers();
        
        // Map Razor Pages
        app.MapRazorPages();
    }
}