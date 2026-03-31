namespace idp.Models;

public class RefreshToken
{
    public int Id { get; set; }
    public string Token { get; set; } = string.Empty;
    public string JwtId { get; set; } = string.Empty;
    public DateTime ExpiryDate { get; set; }
    public bool IsRevoked { get; set; } = false;
    public string UserId { get; set; } = string.Empty;
    public string? ReplacedByToken { get; set; }
    public bool IsUsed { get; set; }
    public bool MfaVerified { get; set; }
    public DateTime CreatedAt { get; set; }
    public string CreatedByIp { get; set; } = string.Empty;
    public string RevokedByIp { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
}