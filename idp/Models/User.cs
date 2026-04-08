using System.ComponentModel.DataAnnotations;

namespace idp.Models;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [MaxLength(50)]
    public required string Email { get; set; } = string.Empty;
    public bool EmailVerified { get; set; }
    [MaxLength(200)]
    public string EmailVerificationTokenHash { get; set; } = string.Empty;
    public DateTime? EmailVerificationTokenExpiry { get; set; }

    [MaxLength(200)]
    public string PasswordResetTokenHash { get; set; } = string.Empty;
    public DateTime? PasswordResetTokenExpiry { get; set; }

    public List<WebAuthnCredential> Credentials { get; set; }
    [MaxLength(200)]
    public required string PasswordHash { get; set; } = string.Empty;

    [MaxLength(30)]
    public string TotpSecret { get; set; } = string.Empty;
    public bool IsTotpEnabled { get; set; }
    public long? LastTotpStepUsed { get; set; }

    public List<string> BackupCodes { get; set; }
}