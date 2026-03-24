namespace idp.Controllers.Requests;

public class AuthorizeRequest
{
    public string Tenant { get; set; }
    public string Client_id { get; set; }
    public string Redirect_uri { get; set; }
    public string Response_type { get; set; }
    public string Scope { get; set; }
    public string State { get; set; }

    // PKCE
    public string Code_challenge { get; set; }
    public string Code_challenge_method { get; set; } // "S256" 
}