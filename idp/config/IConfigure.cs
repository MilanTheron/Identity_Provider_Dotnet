namespace idp.config;

public interface IConfigure {}
public interface IConfigureServices : IConfigure
{
    void ConfigureServices(IConfiguration configuration, IServiceCollection services);
}
public interface IConfigureApp : IConfigure
{
    void ConfigureApp(WebApplication app);
}