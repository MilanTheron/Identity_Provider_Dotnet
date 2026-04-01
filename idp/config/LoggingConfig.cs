namespace idp.config;

public class LoggingConfig : IConfigureServices
{
    public void ConfigureServices(IConfiguration configuration, IServiceCollection services)
    {
        services.AddLogging(loggingBuilder =>
        {
            loggingBuilder.ClearProviders();

            loggingBuilder.AddConsole(options =>
            {
                options.TimestampFormat = "[yyyy-MM-dd HH:mm:ss] ";
            });

            loggingBuilder.AddDebug();

            loggingBuilder.SetMinimumLevel(LogLevel.Information);
        });
    }
}