namespace idp.config;

public class SecurityHeadersConfig : IConfigureApp
{
    public void ConfigureApp(WebApplication app)
    {
        app.Use(async (HttpContext context, RequestDelegate next) =>
        {
            context.Response.OnStarting(() =>
            {
                context.Response.Headers["X-Frame-Options"] = "DENY";
                context.Response.Headers["X-Content-Type-Options"] = "nosniff";
                context.Response.Headers["X-Permitted-Cross-Domain-Policies"] = "none";
                context.Response.Headers["Referrer-Policy"] = "no-referrer";
                context.Response.Headers["Permissions-Policy"] =
                    "camera=(), microphone=(), geolocation=(), payment=()";

                context.Response.Headers["Content-Security-Policy"] =
                    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
                    "img-src 'self' data:; font-src 'self'; connect-src 'self' https:; frame-ancestors 'none'; " +
                    "base-uri 'self'; form-action 'self';";

                if (context.Request.IsHttps)
                {
                    context.Response.Headers["Strict-Transport-Security"] =
                        "max-age=31536000; includeSubDomains";
                }

                return Task.CompletedTask;
            });

            await next(context);
        });
    }
}