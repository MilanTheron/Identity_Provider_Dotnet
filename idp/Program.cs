using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using idp.Data;
using idp.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

// Register authentication services
builder.Services.AddScoped<PasswordService>();
builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<BackupCodeService>();
builder.Services.AddScoped<SecurityService>();

var jwtKey = builder.Configuration["Jwt:Key"]
             ?? throw new InvalidOperationException("Jwt:Key not configured"); // rotate keys periodically or store them securely in Azure Key Vault, AWS KMS, etc.

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = true;

        // Token
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ClockSkew = TimeSpan.FromSeconds(30),

            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],

            ValidateAudience = true,
            ValidAudience = builder.Configuration["Jwt:Audience"],

            ValidateLifetime = true,
            RequireExpirationTime = true,

            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),

            NameClaimType = JwtRegisteredClaimNames.Sub,
        };

        // Token On event
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var jti = context.Principal?.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;

                if (jti == null)
                {
                    context.Fail("Missing jti");
                    return;
                }

                if (!await SecurityService.ValidateJtiAsync(jti))
                {
                    context.Fail("Invalid token");
                }
            }
        };
    });

// Policies
builder.Services.AddAuthorization(options =>
{
    // Fallback: tous les endpoints nécessitent authentification par défaut
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();

    // Policy pour rôles administrateurs
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin")
    );

    // Policy pour utilisateurs authentifiés avec MFA activée
    options.AddPolicy("RequireMfa", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c =>
                c.Type == "mfa" && c.Value == "true"
            )
        )
    );

    // Policy pour endpoints sensibles (modification de mot de passe, tokens)
    options.AddPolicy("SensitiveOperation", policy =>
        policy.RequireAuthenticatedUser()
              .RequireClaim("mfa", "true")
    );
});

builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("auth", opt =>
    {
        opt.Window = TimeSpan.FromMinutes(1);
        opt.PermitLimit = 5;
        opt.QueueLimit = 0;
    });
});

var app = builder.Build();

// FOR DEV ONLY, TO REMOVE LATER
if (args.Contains("--cleanDB"))
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

    // Completely delete the database
    Console.WriteLine("Deleting database...");
    await db.Database.EnsureDeletedAsync();

    // Recreate database schema
    Console.WriteLine("Recreating database...");
    await db.Database.EnsureCreatedAsync();

    Console.WriteLine("Database fully removed and recreated");
    return; // stop app here
}
// FOR DEV ONLY, TO REMOVE LATER

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
} else {
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();

app.Use(async (context, next) =>
{
    // Prevent clickjacking
    context.Response.Headers["X-Frame-Options"] = "DENY";

    // Prevent MIME sniffing
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    
    context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Strict-Transport-Security"] =
        "max-age=31536000; includeSubDomains";

    // Content Security Policy
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self'; " +
        "img-src 'self' data:; " +
        "font-src 'self'; " +
        "connect-src 'self';";

    await next();
});

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();