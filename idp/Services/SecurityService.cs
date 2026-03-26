using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace idp.Services;

public class SecurityService
{
    private static readonly ConcurrentDictionary<string, DateTime> ValidJtis = new();
    
    public static RSA Rsa => _rsa.Value;
    private static readonly Lazy<RSA> _rsa = new(() =>
    {
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build();

        var privateKeyPath = config["Rsa:PrivateKeyPath"];
        if (string.IsNullOrEmpty(privateKeyPath))
            throw new InvalidOperationException("RSA private key path not configured");

        var pem = File.ReadAllText(privateKeyPath);

        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);

        return rsa;
    });

    // JTI validation
    public static Task<bool> ValidateJtiAsync(string jti)
    {
        if (string.IsNullOrEmpty(jti))
            return Task.FromResult(false);

        if (!ValidJtis.TryGetValue(jti, out var expiry))
            return Task.FromResult(false);

        if (DateTime.UtcNow > expiry)
        {
            ValidJtis.TryRemove(jti, out _);
            return Task.FromResult(false);
        }

        return Task.FromResult(true);
    }

    public static Task StoreJtiAsync(string jti, DateTime expiry)
    {
        if (!string.IsNullOrEmpty(jti))
            ValidJtis[jti] = expiry;

        return Task.CompletedTask;
    }

    public Task RevokeJtiAsync(string jti)
    {
        if (!string.IsNullOrEmpty(jti))
            ValidJtis.TryRemove(jti, out _);

        return Task.CompletedTask;
    }
}