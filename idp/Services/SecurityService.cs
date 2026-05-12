using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using idp.Models;
using idp.Data;

namespace idp.Services;

public class SecurityService
{
    private static RSA? _testRsa;

    public static RSA Rsa => _testRsa ?? _rsa.Value;

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

    /// <summary>For unit tests only.</summary>
    public static void UseRsaForTesting(RSA? rsa) => _testRsa = rsa;

    // JTI validation
    public static async Task<bool> ValidateJtiAsync(AppDbContext db, string jti)
    {
        var entry = await db.JwtTokens
            .FirstOrDefaultAsync(x => x.Jti == jti);

        if (entry == null)
            return false;

        if (DateTime.UtcNow > entry.Expiry)
        {
            db.JwtTokens.Remove(entry);
            await db.SaveChangesAsync();
            return false;
        }

        return true;
    }

    public static async Task StoreJtiAsync(AppDbContext db, string jti, DateTime expiry)
    {
        db.JwtTokens.Add(new JwtTokenEntry
        {
            Jti = jti,
            Expiry = expiry
        });

        await db.SaveChangesAsync();
    }
    
    public static async Task RevokeJtiAsync(AppDbContext db, string jti)
    {
        var entry = await db.JwtTokens
            .FirstOrDefaultAsync(x => x.Jti == jti);

        if (entry != null)
        {
            db.JwtTokens.Remove(entry);
            await db.SaveChangesAsync();
        }
    }
}