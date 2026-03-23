using Fido2NetLib;

namespace idp.Controllers.Requests;

public class WebAuthnLoginFinishRequest
{
    public string Username { get; set; }
    public string CredentialId { get; set; }
    public AuthenticatorAssertionRawResponse ClientResponse { get; set; }
}