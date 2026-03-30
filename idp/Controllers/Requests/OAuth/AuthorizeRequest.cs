namespace idp.Controllers.Requests;

public class AuthorizeRequest
{
    public required string Tenant { get; set; }
    public required string ClientId { get; set; }
    public required string RedirectUri { get; set; }
    public required string ResponseType { get; set; }
    public required string Scope { get; set; }
    public required string State { get; set; }

    // PKCE
    public required string CodeChallenge { get; set; }
    public required string CodeChallengeMethod { get; set; } // "S256" 
}