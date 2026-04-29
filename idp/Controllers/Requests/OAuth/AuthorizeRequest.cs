using Microsoft.AspNetCore.Mvc;

namespace idp.Controllers.Requests.OAuth;

public class AuthorizeRequest
{
    [FromQuery(Name = "tenant")]
    public string? Tenant { get; set; }
    [FromQuery(Name = "client_id")]
    public string? ClientId { get; set; }
    [FromQuery(Name = "redirect_uri")]
    public string? RedirectUri { get; set; }
    [FromQuery(Name = "response_type")]
    public string? ResponseType { get; set; }
    [FromQuery(Name = "scope")]
    public string? Scope { get; set; }
    [FromQuery(Name = "state")]
    public string? State { get; set; }
    [FromQuery(Name = "nonce")]
    public string? Nonce { get; set; }

    // PKCE
    [FromQuery(Name = "code_challenge")]
    public string? CodeChallenge { get; set; }
    [FromQuery(Name = "code_challenge_method")]
    public string? CodeChallengeMethod { get; set; } // "S256" 
}