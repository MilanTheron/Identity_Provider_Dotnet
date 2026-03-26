using System.ComponentModel.DataAnnotations;

namespace idp.Models;

public class AuthorizationCode
{
    public int Id { get; set; }
    public required string Code { get; set; }
    public required string ClientId { get; set; }
    public required string RedirectUri { get; set; }
    public required string CodeChallenge { get; set; }
    public required string CodeChallengeMethod { get; set; }
    public required string UserId { get; set; }
    public required bool Used { get; set; }
    public DateTime ExpiresAt { get; set; }
}