using System.ComponentModel.DataAnnotations;

namespace idp.Models;

public class RefreshToken
{
    public int Id { get; set; }
    [MaxLength(30)]
    public string Token { get; set; } = string.Empty;
    [MaxLength(25)]
    public string JwtId { get; set; } = string.Empty;
    public DateTime ExpiryDate { get; set; }
    public bool IsRevoked { get; set; } = false;
    [MaxLength(25)]
    public string UserId { get; set; } = string.Empty;
    [MaxLength(30)]
    public string ReplacedByToken { get; set; } = string.Empty;
    public bool IsUsed { get; set; }
    public bool MfaVerified { get; set; }
    public DateTime CreatedAt { get; set; }
    [MaxLength(20)]
    public string CreatedByIp { get; set; } = string.Empty;
    [MaxLength(20)]
    public string RevokedByIp { get; set; } = string.Empty;
    [MaxLength(15)]
    public string Scope { get; set; } = string.Empty;
}