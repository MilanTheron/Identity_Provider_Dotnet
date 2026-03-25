namespace idp.Controllers.Requests;

public class TokenRequest
{
    public required string ClientId { get; set; }
    public required string GrantType { get; set; }
    public required string Code { get; set; }
    public required string RedirectUri { get; set; }
    public required string CodeVerifier { get; set; }
}