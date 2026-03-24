namespace idp.Models;

public class AuthorizationCode
{
    public int Id { get; set; }
    public string Code { get; set; }
    public string ClientId { get; set; }
    public string RedirectUri { get; set; }
    public string CodeChallenge { get; set; }
    public string CodeChallengeMethod { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string UserId { get; set; }
    public bool used { get; set; }
}