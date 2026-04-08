using System.ComponentModel.DataAnnotations;

namespace idp.Models;

public class AuthorizationCode
{
    public int Id { get; set; }
    [MaxLength(25)]
    public string Code { get; set; } = string.Empty;
    [MaxLength(25)]
    public string ClientId { get; set; } = string.Empty;
    [MaxLength(2048)]
    public string RedirectUri { get; set; } = string.Empty;
    [MaxLength(15)]
    public string CodeChallenge { get; set; } = string.Empty;
    [MaxLength(10)]
    public string CodeChallengeMethod { get; set; } = string.Empty;
    [MaxLength(25)]
    public string UserId { get; set; } = string.Empty;
    [MaxLength(200)]
    public string Scope { get; set; } = string.Empty;
    public bool Used { get; set; } = false;
    public DateTime ExpiresAt { get; set; }
}