namespace idp.Controllers.Requests.OAuth;

public class AuthorizeRequest
{
    public string? Tenant { get; set; }
    public string? ClientId { get; set; }
    public string? RedirectUri { get; set; }
    public string? ResponseType { get; set; }
    public string? Scope { get; set; }
    public string? State { get; set; }

    // PKCE
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; } // "S256" 
}