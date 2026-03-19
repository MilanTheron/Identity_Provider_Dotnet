using System.Security.Cryptography;
using Konscious.Security.Cryptography;
using System.Text;

namespace idp.Services;

public class BackupCodeService
{
    public List<string> GenerateBackupCodes(int count = 10, int codeLength = 12)
    {
        var codes = new List<string>();
        for (int i = 0; i < count; i++)
        {
            codes.Add(GenerateRandomCode(codeLength));
        }
        return codes;
    }
    
    public string HashBackupCode(string code)
    {
        byte[] salt = Convert.FromBase64String("your-fixed-salt-here"); // TODO: Use secure, unique salt from configuration, .env?
        using var hasher = new Argon2id(Encoding.UTF8.GetBytes(code));
        hasher.Salt = salt;
        hasher.DegreeOfParallelism = 8;
        hasher.MemorySize = 65536; // 64 MB... can use Environment.ProcessorCount * 1024 for dynamic memory size
        hasher.Iterations = 5;
        
        var hashBytes = hasher.GetBytes(32);
        var hash = Convert.ToBase64String(hashBytes);
        
        return $"{Convert.ToBase64String(salt)}:{hash}";
    }

    private string GenerateRandomCode(int length)
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
}

