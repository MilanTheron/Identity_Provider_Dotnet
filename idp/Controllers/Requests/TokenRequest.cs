namespace idp.Controllers.Requests;

public class TokenRequest
{
    public string Client_id { get; set; }
    public string Grant_type { get; set; }
    public string Code { get; set; }
    public string Redirect_uri { get; set; }
    public string Code_verifier { get; set; }
}