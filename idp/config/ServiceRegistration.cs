using idp.Services;
using idp.Data;
using Microsoft.EntityFrameworkCore;

namespace idp.config;

public class ServiceRegistration : IConfigureServices
{
    public void ConfigureServices(IConfiguration configuration, IServiceCollection services)
    {
        services.AddControllers();
        services.AddDbContext<AppDbContext>(o =>
            o.UseSqlite(configuration.GetConnectionString("DefaultConnection")));

        services.AddSingleton(sp =>
        {
            var config = sp.GetRequiredService<IConfiguration>();
            return FidoConfig.GetFido2(config);
        });
        
        services.AddScoped<BackupCodeService>();
        services.AddScoped<ErrorService>();
        services.AddSingleton<LoginDelayService>();
        services.AddScoped<PasswordService>();
        services.AddScoped<SecurityService>();
        services.AddScoped<SendEmailService>();
        services.AddScoped<AuthService>();
        services.AddScoped<TokenService>();
        
        services.AddHttpContextAccessor();
    }
}