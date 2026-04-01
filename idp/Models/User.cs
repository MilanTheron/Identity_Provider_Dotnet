using System.ComponentModel.DataAnnotations;

namespace idp.Models;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    [MaxLength(15)]
    public required string Username { get; set; } = string.Empty;
    [MaxLength(25)]
    public string? Email { get; set; }
    public List<WebAuthnCredential> Credentials { get; set; } = new();
    [MaxLength(200)]
    public required string PasswordHash { get; set; } = string.Empty;
    
    [MaxLength(30)]
    public string? TotpSecret { get; set; } // For TOTP
    public bool IsTotpEnabled { get; set; } = false;

    public List<string>? BackupCodes { get; set; } // Hashed backup codes
}
