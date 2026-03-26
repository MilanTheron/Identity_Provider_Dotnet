using Fido2NetLib;

namespace idp.config;
public static class FidoConfig
{
    public static Fido2 GetFido2(IConfiguration config)
    {
        return new Fido2(new Fido2Configuration
        {
            ServerDomain = config["Fido:Domain"],
            ServerName = "Identity_Provider_Dotnet",
            Origins = config.GetSection("Fido:Origins").Get<HashSet<string>>()
        });
    }
}