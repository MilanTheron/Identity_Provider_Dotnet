namespace idp.Controllers.Requests.OAuth;

public class TokenRequest
{
    public string ClientId { get; set; } = string.Empty;
    public string GrantType { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string CodeVerifier { get; set; } = string.Empty;
}