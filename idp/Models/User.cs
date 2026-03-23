using System.ComponentModel.DataAnnotations;

namespace idp.Models;

public class User
{
    public int Id { get; set; }

    [Required, Length(8, maximumLength: 64)]
    public string Username { get; set; } = string.Empty;

    public string? Email { get; set; }
    public List<WebAuthnCredential> Credentials { get; set; } = new();
    public string PasswordHash { get; set; } = string.Empty;

    public string? TotpSecret { get; set; } // For TOTP
    public bool IsTotpEnabled { get; set; } = false;
    
    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LockoutEnd { get; set; }


    public List<string>? BackupCodes { get; set; } // Hashed backup codes
}
