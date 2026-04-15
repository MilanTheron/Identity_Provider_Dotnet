namespace idp.config;

public class PipelineConfig : IConfigureApp
{
    public void ConfigureApp(WebApplication app)
    {
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