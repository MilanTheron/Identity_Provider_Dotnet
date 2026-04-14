using System.ComponentModel.DataAnnotations;

namespace idp.Models;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Device? Device { get; set; }
    
    [MaxLength(50)]
    public required string Email { get; set; }
    public bool EmailVerified { get; set; }
    [MaxLength(200)]
    public string? EmailVerificationTokenHash { get; set; }
    public DateTime? EmailVerificationTokenExpiry { get; set; }

    [MaxLength(200)]
    public string? PasswordResetTokenHash { get; set; }
    public DateTime? PasswordResetTokenExpiry { get; set; }

    public List<WebAuthnCredential>? Credentials { get; set; }
    [MaxLength(200)]
    public required string PasswordHash { get; set; }

    [MaxLength(30)]
    public string? TotpSecret { get; set; }
    public bool IsTotpEnabled { get; set; }
    public long? LastTotpStepUsed { get; set; }
    [MaxLength(200)]
    public string? TotpFallbackTokenHash { get; set; }
    public DateTime? TotpFallbackTokenExpiry { get; set; }

    public List<string>? BackupCodes { get; set; }
}