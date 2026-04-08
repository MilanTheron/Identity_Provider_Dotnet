namespace idp.Controllers.Requests.OAuth;

public class TokenRequest
{
    public string? ClientId { get; set; }
    public string? GrantType { get; set; }
    public string? Code { get; set; }
    public string? RedirectUri { get; set; }
    public string? CodeVerifier { get; set; }
    public string? Scope { get; set; }
}