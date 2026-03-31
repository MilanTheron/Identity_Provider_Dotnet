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

        services.AddScoped<PasswordService>();
        services.AddScoped<TokenService>();
        services.AddScoped<BackupCodeService>();
        services.AddScoped<SecurityService>();
        services.AddScoped<ErrorService>();
    }
}