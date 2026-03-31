using System.Security.Cryptography;
using Konscious.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace idp.Services;

public class PasswordService
{
    public static string HashPassword(string password)
    {
        byte[] salt = new byte[128 / 8];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);

        using var hasher = new Argon2id(Encoding.UTF8.GetBytes(password));
        hasher.Salt = salt;
        hasher.DegreeOfParallelism = 8;
        hasher.MemorySize = 65536; // 64 MB... can user Environment.ProcessorCount for dynamic memory size
        hasher.Iterations = 5;
        
        var hashBytes = hasher.GetBytes(32);
        var hash = Convert.ToBase64String(hashBytes);

        return $"{Convert.ToBase64String(salt)}:{hash}";
    }
    
    public static bool VerifyPassword(string password, string storedHash)
    {
        var parts = storedHash.Split(':');
        if (parts.Length != 2)
            return false;

        try
        {
            var salt = Convert.FromBase64String(parts[0]);
            var hash = parts[1];

            using var testHash = new Argon2id(Encoding.UTF8.GetBytes(password));
            testHash.Salt = salt;
            testHash.DegreeOfParallelism = 8;
            testHash.MemorySize = 65536; // 64 MB... can use Environment.ProcessorCount for dynamic memory size
            testHash.Iterations = 5;
        
            var hashBytes = testHash.GetBytes(32);
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(hash),
                hashBytes
            );
        }
        catch
        {
            return false;
        }
    }
    
    public static async Task<bool> IsWeak(string password)
    {
        bool pwned = await CheckHaveIBeenPwned(password); // true if pwned
        bool regexOk = CheckRegex(password); // true if strong regex
        return pwned || !regexOk; // true if weak or pwned
    }

    private static bool CheckRegex(string password)
    {
        string pattern = @"^(?=.*[A-Z])(?=.*[@$!%*?&^#()[\]{}|\\/\-+_.:;=,~`])(?=.*[0-9])(?=.*[a-z]).{12,}$";
        return Regex.IsMatch(password, pattern);
    }

    // Check if password has ever been in a breach using the Have I Been Pwned API
    private static async Task<bool> CheckHaveIBeenPwned(string password)
    {
        // Hash password with SHA-1
        using var sha1 = SHA1.Create();
        byte[] hashBytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(password));
        string hash = BitConverter.ToString(hashBytes).Replace("-", "").ToUpperInvariant();

        string prefix = hash.Substring(0, 5);
        string suffix = hash.Substring(5);

        using var client = new HttpClient();
        client.DefaultRequestHeaders.Add("Add-Padding", "true");

        var response = await client.GetAsync($"https://api.pwnedpasswords.com/range/{prefix}");
        response.EnsureSuccessStatusCode();

        string body = await response.Content.ReadAsStringAsync();
        var lines = body.Split('\n');

        foreach (var line in lines)
        {
            var parts = line.Split(':');
            if (parts.Length != 2) continue;

            string returnedSuffix = parts[0].Trim();
            if (returnedSuffix.Equals(suffix, StringComparison.OrdinalIgnoreCase))
            {
                // Found in breach
                return true;
            }
        }

        // Not found
        return false;
    }
}

