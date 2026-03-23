using Fido2NetLib;

namespace idp.config;
public static class FidoConfig
{
    public static Fido2 GetFido2(IConfiguration config)
    {
        return new Fido2(new Fido2Configuration
        {
            ServerDomain = config["Fido:Domain"], // Change with actual domain name
            ServerName = "Identity_Provider_Dotnet",
            Origins = new HashSet<string> { config["Fido:Origin"] }
        });
    }
}