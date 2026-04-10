using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using idp.Services;
using idp.Data;

namespace idp.config;

public class JwtAuthConfig : IConfigureServices, IConfigureApp
{
    public void ConfigureServices(IConfiguration configuration, IServiceCollection services)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(configuration["Rsa:PublicKeyPath"]));

        // Add authentication with PolicyScheme that supports both Cookie and JWT
        services.AddAuthentication(options =>
        {
            options.DefaultScheme = "SmartScheme";
            options.DefaultChallengeScheme = "SmartScheme";
        })
        .AddPolicyScheme("SmartScheme", "JWT or Cookie", options =>
        {
            options.ForwardDefaultSelector = context =>
            {
                var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
                if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
                    return JwtBearerDefaults.AuthenticationScheme;

                return "AuthScheme";
            };
        })
        .AddCookie("AuthScheme", options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.LoginPath = "/api/auth/login";
            options.LogoutPath = "/api/auth/logout/session";
        })
        .AddJwtBearer(options =>
        {
            options.RequireHttpsMetadata = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = configuration["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = configuration["Jwt:Audience"],
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new RsaSecurityKey(rsa),
                NameClaimType = JwtRegisteredClaimNames.Sub
            };
            options.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = context =>
                {
                    return Task.CompletedTask;
                },
                OnTokenValidated = async context =>
                {
                    var sp = context.HttpContext.RequestServices;
                    var db = sp.GetRequiredService<AppDbContext>();

                    var userId = context.Principal?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                    var jti = context.Principal?.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
                    var mailVerified = context.Principal?.FindFirst("email_verified")?.Value;

                    if (userId == null || jti == null || mailVerified == null)
                    {
                        context.Fail("Invalid token");
                        return;
                    }

                    var user = await db.Users.FindAsync(userId);

                    if (user == null)
                    {
                        context.Fail("User no longer exists");
                        return;
                    }

                    if (!mailVerified.Equals("true", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Fail("Email not verified");
                        return;
                    }

                    if (!await SecurityService.ValidateJtiAsync(jti))
                        context.Fail("Invalid token");
                }
            };
        });

        services.AddAuthorization(o =>
        {
            o.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser().Build();
            o.AddPolicy("AdminOnly", p => p.RequireRole("Admin"));
            o.AddPolicy("RequireMfa", p => p.RequireClaim("mfa", "true"));
            o.AddPolicy("SensitiveOperation", p => p.RequireAuthenticatedUser());
        });
    }

    public void ConfigureApp(WebApplication app)
    {
        app.UseAuthentication();
        app.UseAuthorization();
    }
}