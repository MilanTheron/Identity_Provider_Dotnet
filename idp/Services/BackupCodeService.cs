using System.Security.Cryptography;
using Konscious.Security.Cryptography;
using System.Text;

namespace idp.Services;

public class BackupCodeService
{
    private readonly ILogger<BackupCodeService> _logger;

    public BackupCodeService(ILogger<BackupCodeService> logger)
    {
        _logger = logger;
    }
    
    public List<string> GenerateBackupCodes(int count = 10, int codeLength = 12)
    {
        _logger.LogDebug("Generating {Count} backup codes with length {CodeLength}", count, codeLength);
        var codes = new List<string>();
        for (int i = 0; i < count; i++)
        {
            codes.Add(GenerateRandomCode(codeLength));
        }
        return codes;
    }
    
    public string HashBackupCode(string code)
    {
        _logger.LogDebug("Hashing backup code with Argon2id");
        var salt = RandomNumberGenerator.GetBytes(16);
        using var hasher = new Argon2id(Encoding.UTF8.GetBytes(code));
        hasher.Salt = salt;
        hasher.DegreeOfParallelism = 8;
        hasher.MemorySize = 65536; // 64 MB... can use Environment.ProcessorCount * 1024 for dynamic memory size
        hasher.Iterations = 5;
        
        var hashBytes = hasher.GetBytes(32);
        var hash = Convert.ToBase64String(hashBytes);
        
        return $"{Convert.ToBase64String(salt)}:{hash}";
    }

    private static string GenerateRandomCode(int length)
    {
        const string validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        using var rng = RandomNumberGenerator.Create();
        var data = new byte[length];
        rng.GetBytes(data);

        var result = new char[length];
        for (int i = 0; i < length; i++)
        {
            result[i] = validChars[data[i] % validChars.Length];
        }
        return new string(result);
    }
    
    public bool VerifyBackupCode(string code, string storedValue)
    {
        try
        {
            var parts = storedValue.Split(':');
            
            if (parts.Length != 2)
                return false;
            
            var salt = Convert.FromBase64String(parts[0]);
            var expectedHash = Convert.FromBase64String(parts[1]);
            
            using var hasher = new Argon2id(Encoding.UTF8.GetBytes(code));
            
            hasher.Salt = salt;
            hasher.DegreeOfParallelism = 8;
            hasher.MemorySize = 65536;
            hasher.Iterations = 5;
            
            var actualHash = hasher.GetBytes(32);
            
            return CryptographicOperations.FixedTimeEquals(
                actualHash,
                expectedHash
            );
        }
        catch
        {
            return false;
        }
    }
}