using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using idp.Services;
using idp.Data;

namespace idp.config;

public class JwtAuthConfig : IConfigureServices
{
    public void ConfigureServices(IConfiguration configuration, IServiceCollection services)
    {
        services.AddSingleton(_ =>
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(configuration["Rsa:PrivateKeyPath"]));
            return rsa;
        });
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
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.None;

                options.LoginPath = "/Auth";
                options.LogoutPath = "/api/auth/logout/session";
                options.ExpireTimeSpan = TimeSpan.FromHours(1);
                options.SlidingExpiration = true;

                options.Events.OnRedirectToLogin = ctx =>
                {
                    ctx.Response.StatusCode = 401;
                    return Task.CompletedTask;
                };

                options.Events.OnRedirectToAccessDenied = ctx =>
                {
                    ctx.Response.StatusCode = 403;
                    ctx.Response.ContentType = "application/json";

                    return ctx.Response.WriteAsync("{\"error\":\"Access denied\"}");
                };
            })
            .AddJwtBearer(options =>
            {
                // options.RequireHttpsMetadata = true;
                
                options.MapInboundClaims = false;
                
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = configuration["Jwt:Issuer"],
                    
                    ValidateAudience = false,
                    
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    
                    NameClaimType = JwtRegisteredClaimNames.Sub
                };
                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = context =>
                    {
                        var rsa = context.HttpContext.RequestServices.GetRequiredService<RSA>();
                        
                        context.Options.TokenValidationParameters.IssuerSigningKey =
                            new RsaSecurityKey(rsa);
                        
                        return Task.CompletedTask;
                    },
                    OnAuthenticationFailed = context =>
                    {
                        Console.WriteLine("JWT authentication failed: " + context.Exception.Message);
                        return Task.CompletedTask;
                    },
                    OnChallenge = context =>
                    {
                        context.HandleResponse();
                        
                        context.Response.StatusCode = 401;
                        context.Response.ContentType = "application/json";
                        
                        var msg = context.ErrorDescription ?? context.Error ?? "Unauthorized";
                        
                        return context.Response.WriteAsync($"{{\"error\": \"{msg}\"}}");
                    },
                    OnTokenValidated = async context =>
                    {
                        var principal = context.Principal;
                        if (principal == null)
                        {
                            context.Fail("No principal");
                            return;
                        }
                        
                        var clientId = principal?.FindFirst("client_id")?.Value;
                        string? aud = principal?.FindFirst("aud")?.Value;

                        if (aud == null && context.SecurityToken is JwtSecurityToken jwt)
                            aud = jwt.Audiences.FirstOrDefault();
                        
                        if (string.IsNullOrEmpty(clientId))
                        {
                            context.Fail("Missing client_id");
                            return;
                        }
                        
                        if (aud != clientId)
                        {
                            context.Fail($"Invalid audience. Expected {clientId}, got {aud}");
                            return;
                        }
                        
                        var userIdStr = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                        var jti = principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
                        
                        if (string.IsNullOrEmpty(userIdStr) || string.IsNullOrEmpty(jti))
                        {
                            context.Fail("Missing sub or jti");
                            return;
                        }
                        
                        if (!Guid.TryParse(userIdStr, out var userId))
                        {
                            context.Fail("Invalid user id");
                            return;
                        }
                        
                        var db = context.HttpContext.RequestServices.GetRequiredService<AppDbContext>();
                        
                        var user = await db.Users.FindAsync(userId);
                        if (user == null)
                        {
                            context.Fail("User no longer exists");
                            return;
                        }
                        
                        // Only enforce JTI for access tokens
                        var scope = principal.FindFirst("scope")?.Value;

                        var requiresJtiValidation =
                            scope?.Contains("offline_access") == true ||
                            scope?.Contains("admin") == true;

                        if (requiresJtiValidation)
                        {
                            if (!await SecurityService.ValidateJtiAsync(db, jti))
                                context.Fail("Invalid token");
                        }
                    }
                };
            });
        services.AddAuthorization(o =>
        {
            o.DefaultPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
            o.AddPolicy("AdminOnly", p => p.RequireRole("Admin"));
            o.AddPolicy("RequireMfa", p => p.RequireClaim("mfa", "true"));
            o.AddPolicy("SensitiveOperation", p => p.RequireAuthenticatedUser());
        });
    }
}