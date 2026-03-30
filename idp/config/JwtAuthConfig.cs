using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using idp.Services;

namespace idp.config;

public class JwtAuthConfig : IConfigureServices, IConfigureApp
{
    public void ConfigureServices(IConfiguration configuration, IServiceCollection services)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(configuration["Rsa:PublicKeyPath"]));

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
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
                        var jti = context.Principal?.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
                        if (jti == null || !await SecurityService.ValidateJtiAsync(jti))
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