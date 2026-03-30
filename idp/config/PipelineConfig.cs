namespace idp.config;

public class PipelineConfig : IConfigureApp
{
    public void ConfigureApp(WebApplication app)
    {
        // Exception handling / HSTS / HTTPS
        app.UseExceptionHandler("/Error");
        app.UseHsts();
        app.UseHttpsRedirection();

        // Rate Limiter
        app.UseRateLimiter();
        
        // Authentication & authorization
        app.UseAuthentication();
        app.UseAuthorization();

        // Map controllers
        app.MapControllers();
    }
}